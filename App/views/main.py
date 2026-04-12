from flask import Blueprint, render_template
from ..services.state import app_state

main_views = Blueprint('main', __name__)


@main_views.route('/')
def dashboard():
    return render_template(
        'dashboard.html',
        page='dashboard',
        latest_alert=app_state.latest_alert
    )


@main_views.route('/visualizations')
def visualizations():
    return render_template(
        'visualizations.html',
        page='visualizations',
        latest_alert=app_state.latest_alert
    )


@main_views.route('/connection')
def connection():
    return render_template(
        'connection.html',
        page='connection',
        latest_alert=app_state.latest_alert
    )


@main_views.route('/alerts')
def alerts():
    return render_template(
        'alerts.html',
        page='alerts',
        latest_alert=app_state.latest_alert
    )

'''
from flask import Blueprint, render_template
from ..services.state import app_state

main_views = Blueprint('main', __name__)


@main_views.route('/')
def dashboard():
    return render_template('dashboard.html', page='dashboard', latest_alert=app_state.latest_alert)


@main_views.route('/visualizations')
def visualizations():
    return render_template('visualizations.html', page='visualizations', latest_alert=app_state.latest_alert)


@main_views.route('/connection')
def connection():
    return render_template('connection.html', page='connection', latest_alert=app_state.latest_alert)
'''