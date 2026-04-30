from __future__ import annotations

import io
from datetime import datetime
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from reportlab.lib.pagesizes import letter
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas

from .plot_service import build_report_bundle


def line_chart(points, title, y_label='Packets'):
    '''
    Returns png bytes for a line chart
    '''
    fig, ax = plt.subplots(figsize=(8.5, 3.2))
    x = [p['x'] for p in points]
    y = [p['y'] for p in points]
    ax.plot(x, y, marker='o')
    ax.set_title(title)
    ax.set_ylabel(y_label)
    ax.tick_params(axis='x', rotation=35)
    fig.tight_layout()
    buf = io.BytesIO()
    fig.savefig(buf, format='png', dpi=140)
    plt.close(fig)
    buf.seek(0)
    return buf


def bar_chart(counts, title):
    '''
    Returns png bytes for a bar chart
    '''
    fig, ax = plt.subplots(figsize=(8.0, 3.2))
    labels = list(counts.keys())
    values = list(counts.values())
    ax.bar(labels, values)
    ax.set_title(title)
    ax.set_ylabel('Count')
    ax.tick_params(axis='x', rotation=35)
    fig.tight_layout()
    buf = io.BytesIO()
    fig.savefig(buf, format='png', dpi=140)
    plt.close(fig)
    buf.seek(0)
    return buf


def pie_chart(counts, title):
    '''
    Returns png bytes for a pie chart
    '''
    safe = {k: v for k, v in counts.items() if v > 0}
    if not safe:
        safe = {'No Data': 1}
    fig, ax = plt.subplots(figsize=(5.0, 4.0))
    ax.pie(list(safe.values()), labels=list(safe.keys()), autopct='%1.0f%%')
    ax.set_title(title)
    fig.tight_layout()
    buf = io.BytesIO()
    fig.savefig(buf, format='png', dpi=140)
    plt.close(fig)
    buf.seek(0)
    return buf


def without_benign(counts):
    '''
    Removes benign from graph counts.
    '''
    return {k: v for k, v in counts.items() if str(k).lower() != 'benign'}


def write_wrapped(pdf, text, x, y, width=90, step=12):

    '''
    Writes lines to the pdf
    '''

    line = ''
    for word in str(text).split():
        test = f'{line} {word}'.strip()
        if len(test) > width:
            pdf.drawString(x, y, line)
            y -= step
            line = word
        else:
            line = test
    if line:
        pdf.drawString(x, y, line)
        y -= step
    return y


def draw_image(pdf, img_bytes, x, y, w, h):
    '''
    Draws an image on the pdf
    '''
    if y - h < 60:
        pdf.showPage()
        y = 730
    pdf.drawImage(ImageReader(img_bytes), x, y - h, width=w, height=h)
    return y - h - 20


def build_report_pdf(snapshot, start_date=None, end_date=None):
    '''
    Builds the PDF report on export.
    '''

    settings = snapshot['settings']
    bundle = build_report_bundle(
        snapshot['processed_flows'],
        start_date,
        end_date,
        settings.get('poll_seconds', 3),
    )

    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    y = height - 40

    pdf.setFont('Helvetica-Bold', 16)
    pdf.drawString(40, y, f"Report of data recorded up to {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    y -= 28

    pdf.setFont('Helvetica-Bold', 12)
    pdf.drawString(40, y, 'Traffic Summary-')
    y -= 18
    pdf.setFont('Helvetica', 10)
    summary_lines = [
        f"Flows Read - {snapshot['summary']['total_flows']}",
        f"Benign Flows - {snapshot['summary']['benign_count']}",
        f"Non-Benign Flows - {snapshot['summary']['not_benign_count']}",
        f"Current Mode - {snapshot['summary'].get('active_mode', '-')}",
    ]
    for line in summary_lines:
        pdf.drawString(50, y, line)
        y -= 14

    y -= 8
    pdf.setFont('Helvetica-Bold', 12)
    pdf.drawString(40, y, 'Connection Summary-')
    y -= 18
    pdf.setFont('Helvetica', 10)
    connection_lines = [
        f"Host URL - {settings.get('flask_host', '127.0.0.1')}:{settings.get('flask_port', 5000)}",
        f"Sender URL - {settings.get('sender_target', '-')}",
        f"Detection API URL - {settings.get('security_api_url', '-')}",
        f"Correlation Window Minutes - {settings.get('correlation_window_minutes', 5)}",
        f"LLM Model - {settings.get('llm_model', '-')}",
        f"LLM Base URL - {settings.get('llm_base_url', '-')}",
        f"LLM API key - {settings.get('llm_api_key', '-')}",
        f"Poll Seconds - {settings.get('poll_seconds', 3)}",
    ]
    for line in connection_lines:
        y = write_wrapped(pdf, line, 50, y)

    y -= 8
    pdf.setFont('Helvetica-Bold', 12)
    pdf.drawString(40, y, 'Graphs-')
    y -= 18

    y = draw_image(pdf, line_chart(bundle['packet_activity'], 'Packet Activity'), 40, y, 520, 180)
    y = draw_image(pdf, line_chart(bundle['per_second'], 'Total Packets Per Second'), 40, y, 520, 180)
    y = draw_image(pdf, line_chart(bundle['per_minute'], 'Total Packets Per Minute'), 40, y, 520, 180)
    y = draw_image(pdf, line_chart(bundle['per_hour'], 'Total Packets Per Hour'), 40, y, 520, 180)
    y = draw_image(pdf, line_chart(bundle['per_day'], 'Total Packets Per Day'), 40, y, 520, 180)
    y = draw_image(pdf, bar_chart(without_benign(bundle['attack_counts']), 'Detected Classes'), 40, y, 520, 180)
    y = draw_image(pdf, pie_chart(bundle['attack_counts'], 'Flow Type Distribution'), 130, y, 320, 220)

    pdf.showPage()
    y = 740
    pdf.setFont('Helvetica-Bold', 12)
    pdf.drawString(40, y, 'Individual days -')
    y -= 20

    for day in bundle['individual_days']:
        if y < 180:
            pdf.showPage()
            y = 740
        pdf.setFont('Helvetica-Bold', 11)
        pdf.drawString(40, y, day['day'])
        y -= 16
        y = draw_image(pdf, pie_chart(day['counts'], f"{day['day']} Pie"), 40, y, 220, 160)
        y = draw_image(pdf, bar_chart(without_benign(day['counts']), f"{day['day']} Bar"), 280, y + 180, 260, 160)
        y = draw_image(pdf, line_chart(day['hour_series'], f"{day['day']} Hourly Packets"), 40, y, 500, 170)

    pdf.showPage()
    y = 740
    pdf.setFont('Helvetica-Bold', 12)
    pdf.drawString(40, y, 'Flows, Alerts, Insights -')
    y -= 18
    pdf.setFont('Helvetica', 9)

    sections = [
        ('Flows', [str(item) for item in snapshot['feed']]),
        ('Alerts', [str(item) for item in snapshot['alerts']]),
        ('Insights', [str(item) for item in snapshot['insight_history']]),
    ]
    for title, rows in sections:
        if y < 80:
            pdf.showPage()
            y = 740
        pdf.setFont('Helvetica-Bold', 11)
        pdf.drawString(40, y, title)
        y -= 14
        pdf.setFont('Helvetica', 9)
        if not rows:
            pdf.drawString(50, y, 'No data')
            y -= 12
        else:
            for row in rows[:200]:
                if y < 60:
                    pdf.showPage()
                    y = 740
                    pdf.setFont('Helvetica', 9)
                y = write_wrapped(pdf, row, 50, y, width=105, step=11)
        y -= 10

    pdf.save()
    buffer.seek(0)
    return buffer


def save_report_pdf(snapshot, start_date=None, end_date=None):

    '''
    Takes the buffer with the pdf bytes and creates a pdf file in the predetermined path
    '''

    pdf_bytes = build_report_pdf(snapshot, start_date, end_date)
    base_dir = Path(__file__).resolve().parents[2]
    export_dir = base_dir / 'reports' / 'exports'
    export_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    file_path = export_dir / f'douen_report_{stamp}.pdf'
    with open(file_path, 'wb') as handle:
        handle.write(pdf_bytes.getvalue())
    return str(file_path)
