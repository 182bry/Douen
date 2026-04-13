from App import create_app
from App.database import db
from App.models.user import User

app = create_app()

with app.app_context():
    existing = db.session.execute(
        db.select(User).filter_by(username='admin')
    ).scalar_one_or_none()

    if existing:
        print("User 'admin' already exists.")
    else:
        user = User(username='admin', password='admin123')
        db.session.add(user)
        db.session.commit()
        print("Created user: admin / admin123")
        print("this password will be changed production!")