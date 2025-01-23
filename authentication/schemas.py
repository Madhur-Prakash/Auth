def user(item) -> dict:
    return {
        "_id": str(item["_id"]),
        "full_name": item["full_name"],
        "email": item["email"],
        "password": item["password"],
        "disabled": item.get("disabled", False)
    }
        

def userEntity(item) -> list:
    return[user(item) for item in item] 