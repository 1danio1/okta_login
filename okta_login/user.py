from flask_login import UserMixin
from dataclasses import dataclass

# Simulate user database
USERS_DB = {}

@dataclass
class User(UserMixin):
    id: str
    name: str
    email: str
    def claims(self):
        return {
            "name": self.name,
            "email": self.email,
        }.items()

    @staticmethod
    def get(user_id):
        return USERS_DB.get(user_id)

    @staticmethod
    def create(user_id, name, email):
        USERS_DB[user_id] = User(user_id, name, email)
