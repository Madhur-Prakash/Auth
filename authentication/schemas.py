def user(item) -> dict:
    return {
        "_id": str(item["_id"]),
        "full_name": item["full_name"],
        "user_name": item["user_name"],
        "email": item["email"],
        "password": item["password"],
        "password2": item["password2"],
        "phone_number": item["phone_number"],
        "disabled": item.get("disabled", False)
    }
        

def userEntity(item) -> list:
    return[user(item) for item in item] 