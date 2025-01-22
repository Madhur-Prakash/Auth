def user(item) -> dict:
    return {
        "_id": str(item["_id"]),
        "full_name": item["full_name"],
        "email": item["email"],
        "password": item["password"],
        "password2": item["password2"],
        "profile_picture": item["profile_picture"],
        "timestramp": item["timestramp"]
    }

def userEntity(item) -> list:
    return[user(item) for item in item] 