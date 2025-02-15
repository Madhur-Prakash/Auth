def user(item) -> dict:
    return {
        "_id": str(item["_id"]),
        "full_name": item["full_name"],
        "patient_user_name": item["patient_user_name"],
        "email": item["email"],
        "password": item["password"],
        "password2": item["password2"],
        "phone_number": item["phone_number"],
        "disabled": item.get("disabled", False)
    }
        

def patientEntity(item) -> list:
    return[user(item) for item in item] 