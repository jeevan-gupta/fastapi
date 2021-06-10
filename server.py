#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import traceback
import uuid
from datetime import date, datetime, time, timedelta
from pprint import pprint as pp
from typing import Optional

import bcrypt
from decouple import config
from fastapi import FastAPI, Depends, HTTPException, status, Response, Cookie, Body
from fastapi.encoders import jsonable_encoder
from fastapi.middleware.cors import CORSMiddleware
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from jose import jwt
from starlette.responses import JSONResponse

from construction_management.deployment.authentication import authenticate_user, create_access_token, \
    OAuth2PasswordBearerWithCookie
from construction_management.deployment.server_models import Connect, GetProjectDetails, ResetEmailSchema, \
    ResetPasswordSchema, \
    UpdateDeletedValueModel, UpdateEditedValueModel, UpdateMeasurementValueModel, GetMeasurementValueModel, \
    LoginInputDataModel, RegisterProjectSiteDetails, AddWorkContent, ConstructionProgress, UpdateWorkContent, \
    UpdateSystemState, AddLaserData, GetFeedback ,UpdateProjectSiteDetails

tags_metadata = [
    {
        "name": "Authentication",
        "description": "Logic for Login, Reset password and Logout is written here."
    },
    {
        "name": "Main Page",
        "description": "Main page for selecting Construction Project & Create New Project"
    },
    {
        "name": "Dashboard",
        "description": "Apis for listing latest information"
    },
    {
        "name": "Progress Management",
        "description": "Apis for Work Progress page"
    },
    {
        "name": "System Administrator",
        "description": "Apis for controlling and viewing the laser system"
    },
    {
        "name": "Quality Control",
        "description": "Apis for inspecting Quality checks "
    },
    {
        "name": "Feedback",
        "description": "Feedback data collection"
    }
]

# oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login")
oauth2_scheme = OAuth2PasswordBearerWithCookie(tokenUrl="/api/auth/login")

# This is the name used in uvicorn
app = FastAPI(
    title="Coollaser Construction Management Server",
    description="Apis for Construction Management Application",
    docs_url="/bdocs",
    version="1.0.0",
    openapi_tags=tags_metadata
)

# Using decouple lib to get environment variables from .env file
conf = ConnectionConfig(
    MAIL_USERNAME=config("FAST_API_MAIL_USERNAME"),
    MAIL_PASSWORD=config("FAST_API_MAIL_PASSWORD"),
    MAIL_PORT=config("FAST_API_MAIL_PORT"),
    MAIL_SERVER=config("FAST_API_MAIL_SERVER"),
    MAIL_TLS=False,
    MAIL_SSL=True,
    MAIL_FROM=config("FAST_API_MAIL_FROM")
)

# Imp while deploying the app since setting cookie depends upon these origins
origins = [
    'http://localhost:3000',
    'http://test.coollaser.com',
    'https://test.coollaser.com'
]

# App Middleware for setting up production app
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB URL (DOIC connection - Use VPN for this)
client = Connect.get_connection()

# Databases and Collections
db = client["icsp"]
coollaser_inventories_db = client["coollaser_inventories"]
coollaser_construction_db = client["coollaser_construction"]

project_site_details_collection = coollaser_construction_db["project_site_details_collection"]
quality_records_collection = coollaser_construction_db["quality_records"]
menu_collection = coollaser_construction_db["menu_items"]

system_collection = coollaser_construction_db["system_state"]
construction_rate_coll = coollaser_construction_db["construction_rate"]
construction_progress_coll = coollaser_construction_db["construction_progress"]
construction_env_coll = coollaser_construction_db["construction_environment"]
laser_data_coll = coollaser_construction_db['laser_data']

# Use for test purpose only
feedbacks_coll = coollaser_construction_db['feedbacks']
# Test Collection for progress managment
construction_progress_coll_test = coollaser_construction_db["construction_progress_test"]

users_collection = db["users"]

# Get the current working directory
CWD = os.getcwd()


@app.get("/", response_model=dict)
def root():
    response = dict()
    response["message"] = app.description
    response["status"] = status.HTTP_200_OK
    return response


@app.post("/api/auth/login", tags=["Authentication"])
async def login(form_data: LoginInputDataModel):
    user = await authenticate_user(form_data.username, form_data.password)
    ACCESS_TOKEN_EXPIRE_MINUTES = 100

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="InCorrect username or password",
            headers={"WWW-Authenticate": "Bearer"}
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires)

    content = {"name": user["name"], "email": user["username"],
               "role": user["role"]}
    response = JSONResponse(content=content)
    print(content)
    response.set_cookie(key="access_token",
                        value=f"Bearer {access_token}", expires=6000)

    return response


@app.post("/api/scheme/auth/forgot_password", tags=["Authentication"])
async def forget_password(email: ResetEmailSchema) -> JSONResponse:
    user = await users_collection.find_one({"email": email.email[0]})

    if user:
        forgot_token = jwt.encode(
            {'user': email.email[0], 'exp': datetime.utcnow(
            ) + timedelta(minutes=120)},
            config("SECRET_KEY"))  # decouple lib to get environment variables

        message = MessageSchema(
            subject="[Construction Managment Application] Reset Your Password",
            recipients=email.dict().get("email"),
            body=f""" 
            <div marginheight="0" topmargin="0" marginwidth="0" style="margin: 0px; background-color: #f2f3f8;" leftmargin="0">
                <table cellspacing="0" border="0" cellpadding="0" width="100%" bgcolor="#f2f3f8"
                    style="@import url(https://fonts.googleapis.com/css?family=Rubik:300,400,500,700|Open+Sans:300,400,600,700); font-family: 'Open Sans', sans-serif;">
                    <tr>
                        <td>
                            <table style="background-color: #f2f3f8; max-width:670px;  margin:0 auto;" width="100%" border="0"
                                align="center" cellpadding="0" cellspacing="0">
                                <tr>
                                    <td style="height:20px;">&nbsp;</td>
                                </tr>
                                <tr>
                                    <td style="text-align:center;">
                                      <a href="https://toyokoh.com" title="logo" target="_blank">
                                        <img width="80" src="https://onecareer.imgix.net/uploads/company/square_logo/89912/1611816413-TOYOKOH_logoS_4c_(1).png" title="logo" alt="logo">
                                      </a>
                                    </td>
                                </tr>
                                <tr>
                                    <td style="height:20px;">&nbsp;</td>
                                </tr>
                                <tr>
                                    <td>
                                        <table width="95%" border="0" align="center" cellpadding="0" cellspacing="0"
                                            style="max-width:670px;background:#fff; border-radius:3px; text-align:center; -webkit-box-shadow:0 6px 18px 0 rgba(0,0,0,.06); -moz-box-shadow:0 6px 18px 0 rgba(0,0,0,.06); box-shadow:0 6px 18px 0 rgba(0,0,0,.06);">
                                            <tr>
                                                <td style="height:40px;">&nbsp;</td>
                                            </tr>
                                            <tr>
                                                <td style="padding:0 35px;">
                                                    <h1 style="color:#1e1e2d; font-weight:500; margin:0;font-size:32px;font-family:'Rubik',sans-serif;">You have
                                                        requested to reset your password</h1>
                                                    <span
                                                        style="display:inline-block; vertical-align:middle; margin:29px 0 26px; border-bottom:1px solid #cecece; width:100px;"></span>
                                                    <p style="color:#455056; font-size:15px;line-height:24px; margin:0;">
                                                        A unique link to reset your password has been generated for you. To reset your password, click the 
                                                        following link and follow the instructions.
                                                    </p>
                                                    <a href="{config("DOMAIN")}/reset-password/?token={forgot_token}" 
                                                        style="background:#0075c2; text-decoration:none !important; 
                                                        font-weight:500; margin-top:35px; 
                                                        color:#fff;text-transform:uppercase;
                                                         font-size:14px;padding:10px 
                                                        24px;display:inline-block;border-radius:50px;">
                                                        Reset Password
                                                    </a>
                                                    <p style="color:#455056; font-size:11px;line-height:24px; margin:0;">
                                                        If you did not initiate this reset password, Kindly ignore this email and 
                                                        no changes will be applied to your account.
                                                    </p> 
                                                </td>
                                            </tr>
                                            <tr><td style="height:40px;">&nbsp;</td></tr> 
                                        </table>
                                        </td> 
                                        <tr><td style="height:20px;">&nbsp;</td></tr> 
                                        <tr>
                                            <td style="text-align:center;">
                                                <p style="font-size:14px; color:rgba(69, 80, 86, 0.7411764705882353); line-height:18px; 
                                                        margin:0 0 0;">&copy; <strong>www.toyokoh.com</strong>
                                                </p>
                                            </td>
                                        </tr>
                                        <tr><td style="height:20px;">&nbsp;</td></tr>
                            </table>
                        </td>
                    </tr>
                </table>    
            </div>
             """,
            subtype="html"
        )

        fm = FastMail(conf)
        await fm.send_message(message)
        return JSONResponse(status_code=200, content={"message": "Email has been sent!"})
    else:
        return JSONResponse(status_code=400, content={"message": "Invalid Email!"})


@app.post("/api/scheme/auth/reset_password/{reset_token}", tags=["Authentication"])
async def reset_password(reset_token: str, password: ResetPasswordSchema) -> JSONResponse:
    pwd = password.password_one
    if pwd:
        _hashed_password = bcrypt.hashpw(
            pwd.encode('utf-8'), bcrypt.gensalt())
        try:
            email = jwt.decode(reset_token, config('SECRET_KEY'), options={
                "verify_signature": False})['user']

            await users_collection.find_one_and_update(
                {"email": email},
                {"$set": {
                    "pwd": _hashed_password
                }}, upsert=True
            )
        except Exception as e:
            print(e)
            return JSONResponse(status_code=401, content={"message": "fail"})

        return JSONResponse(status_code=200, content={"message": "success"})
    else:
        return JSONResponse(status_code=401, content={"message": "fail"})


@app.get("/api/auth/protected-route", tags=["Authentication"])
async def verifyAuth(token: str = Depends(oauth2_scheme), user: Optional[str] = Cookie(None)):
    print(user)

    try:
        if token:
            response = {"msg": "success"}
            return response

    except Exception as e:
        print(e)
        response = {"msg": "fail"}
        return response


@app.get("/api/auth/logout", tags=["Authentication"])
async def logout(response: Response, token: str = Depends(oauth2_scheme)):
    try:
        if token:
            response.delete_cookie("access_token")
            response = {"message": "success"}
            return response
        else:
            raise Exception("TokenNotFound")
    except Exception as e:
        print(e)
        return JSONResponse(status_code=401, content={"message": "fail"})


@app.post("/api/register/register_project_site", tags=["Main Page"])
async def register_site(project_site_details: RegisterProjectSiteDetails):
    try:
        const_area = []
        for row in project_site_details.cons_area:
            # print(len(project_site_details.select_units))
            d = {
                "cons_area": row.cons_area,
                "value": 0 if row.value == '' else row.value
            }
            const_area.append(d)
        area = ["Select"]
        for row in project_site_details.area:
            area.append(row.area)

        # This is must because we need to store date & time as datetime format
        site_start_date = datetime.strptime(
            project_site_details.start_date_time, '%Y-%m-%d')
        # print(site_start_date)
        site_end_date = datetime.strptime(
            project_site_details.end_date_time, '%Y-%m-%d')
        # print(site_end_date)

        data = {
            "_id": project_site_details.id,
            "project_name": project_site_details.project_name,
            "start_date_time": site_start_date,
            "end_date_time": site_end_date,
            "select_units": project_site_details.select_units,
            "cons_area": const_area,
            "measurement_area": area,
            "work_content": ["機材搬入", "機材搬出", "作業準備", "照射作業", "段取替え", "休憩", "片付け", "消耗品交換", "システムエラー", "その他"]
        }

        project_site_details_collection.insert_one(data)

        return {"msg": "success"}

    except Exception as e:
        print(e)
        response = dict()
        response["message"] = "Error" + str(e)
        response["status"] = status.HTTP_400_BAD_REQUEST
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST,
                            content=jsonable_encoder(response))


@app.get("/api/get_all_project_name", tags=["Main Page"])
async def get_all_site_name(token: str = Depends(oauth2_scheme)):
    try:
        if token:
            project_names = project_site_details_collection.find(
                {}, {"_id": 1, "project_name": 1})
            project_names_list = await project_names.to_list(None)

            project_data = [{'_id': "None", "project_name": "Select"}]

            for items in project_names_list:
                project_data.append(items)

            return project_data
        else:
            raise Exception("TokenNotFound")
    except Exception as e:
        print(e)
        response = dict()
        response["message"] = "Error" + str(e)
        response["status"] = status.HTTP_400_BAD_REQUEST

        return response




# Get All Project Details 

@app.get("/api/get_all_project_details")
async def get_all_project_details():
    project_details = project_site_details_collection.find(
        {}, {"_id": 1, "project_name": 1, "start_date_time" : 1, "end_date_time": 1})
    project_details_list = await project_details.to_list(None)
    print(project_details_list)

    return project_details_list

    



# Update Project Details

@app.put("/api/update_all_details/{_id}", response_model=RegisterProjectSiteDetails)
async def update_all_details(_id: str, project: UpdateProjectSiteDetails = Body(...)):
    project = {k: v for k, v in project.dict().items() if v is not None}
    if len(project) >= 1:
        update_result = await db["project_site_details_collection"].update_one({"id": _id}, {"$set": project})
        if update_result.modified_count == 1:
            if (
                updated_project := await db["project_site_details_collection"].find_one({"id": _id})
            ) is not None:
                return updated_project
    if (existing_project := await db["project_site_details_collection"].find_one({"id": _id})) is not None:
        return existing_project
    raise HTTPException(status_code=404, detail=f"Project {_id} not found")







@app.get("/api/get_unit_name/{project_id}", tags=["Dashboard"])
async def get_unit_name(project_id: str, token: str = Depends(oauth2_scheme)):
    try:

        if token:
            print(project_id)

            unit_names = await project_site_details_collection.find_one(
                {'_id': project_id},
                {'_id': 0, 'select_units': 1}
            )

            unit_names_list = []

            for i in unit_names["select_units"]:
                unit_name_dict = {
                    "label": i,
                    "value": i
                }
                unit_names_list.append(unit_name_dict)

            return unit_names_list

    except Exception as e:
        print(e)
        response = dict()
        response["message"] = "Error" + str(e)
        response["status"] = status.HTTP_400_BAD_REQUEST
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST,
                            content=jsonable_encoder(response))


@app.get("/api/role/{role}", tags=["Dashboard"])
async def get_menu_items(role: str, token: str = Depends(oauth2_scheme)):
    try:
        # print(role)
        menu = await menu_collection.find_one({'_id': role})

        return menu

    except Exception as e:
        print(e)
        response = dict()
        response["message"] = "Error" + str(e)
        response["status"] = status.HTTP_400_BAD_REQUEST
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST,
                            content=jsonable_encoder(response))


@app.get('/api/scheme/construction/environment', tags=["Dashboard"])
async def environment_data(token: str = Depends(oauth2_scheme)):
    try:

        res = construction_env_coll.find(
            {}, {"_id": 0}).sort('datetime', -1).limit(10)

        environment_data_list = await res.to_list(None)

        # for x in res:
        #     # pp(x)
        #     environment_data_list.append(x)

        return JSONResponse(status_code=status.HTTP_200_OK,
                            content=jsonable_encoder(environment_data_list))

    except Exception as e:
        print(e)
        return e


@app.get('/api/scheme/construction/construction_data', tags=["Dashboard"])
async def construction_data(token: str = Depends(oauth2_scheme)):
    try:
        if token:
            cons_data = construction_env_coll.find({})

            cons_data = await cons_data.to_list(None)

            time_list = []
            temp_list = []
            hum_list = []
            pres_list = []
            name_list = []

            for x in cons_data:
                time_list.append(x['datetime'])
                temp_list.append(x['temperature'])
                hum_list.append(x['humidity'])
                pres_list.append(x['pressure'] / 100)
                name_list.append(x['name'])

            response = jsonable_encoder({
                "timestamp": time_list,
                "temperature": temp_list,
                "humidity": hum_list,
                "pressure": pres_list,
                "name": name_list
            })

            return response

    except Exception as e:
        print(e)
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST,
                            content=jsonable_encoder({"message": "Error"}))


@app.get("/api/scheme/construction/dashboard/{project_site_id}/{unit_name}", tags=["Dashboard"])
async def get_dashboard_data(project_site_id, unit_name, token: str = Depends(oauth2_scheme)):
    try:
        if token:

            if unit_name and project_site_id:
                res = system_collection.find(
                    {'project_site_id': project_site_id, 'unit_name': unit_name}).sort('datetime', -1).limit(1)

                res_list = await res.to_list(None)
                # pp(res_list)

                for i in res_list:
                    return i

            else:
                print("No Unit name or Project Site.")

    except Exception as e:
        print(e)
        response = dict()
        response["message"] = "Error:" + str(e)
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content=jsonable_encoder(response))


@app.post('/api/scheme/construction/system_state/edit/{system_id}', tags=["Dashboard"])
async def edit_system_states(system_id, update_content: UpdateSystemState = Body(...),
                             token: str = Depends(oauth2_scheme)):
    try:
        if token:
            data = jsonable_encoder(update_content)

            pp(data)

            updated_date = datetime.strptime(
                data["datetime"], '%Y-%m-%dT%H:%M:%S')
            data["datetime"] = updated_date
            # print(updated_date)
            # print(type(updated_date))

            res = await system_collection.update_one(
                {"_id": int(system_id)}, {"$set": data})

            print("Updated " + str(res.modified_count) +
                  " records for ID no: " + str(system_id))

            return JSONResponse(status_code=status.HTTP_200_OK,
                                content=jsonable_encoder({"message": "Updated"}))

    except Exception as e:
        print(e)
        response = dict()
        response["message"] = "Error" + str(e)
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST,
                            content=jsonable_encoder(response))


@app.get("/api/get_measurement_area/{project_id}", tags=[""])
async def get_measurement_location(project_id: str, token: str = Depends(oauth2_scheme)):
    try:
        if token:
            # print(project_id)
            area = ["Select"]
            measurement_areas = await project_site_details_collection.find_one(
                {'_id': project_id},
                {'_id': 0, 'measurement_area': 1}
            )

            # print(project_id)
            measurement_areas = area + measurement_areas["measurement_area"]
            # print(measurement_areas)

            return measurement_areas

    except Exception as e:
        print(e)
        response = dict()
        response["message"] = "Error" + str(e)
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST,
                            content=jsonable_encoder(response))


@app.post("/api/update_measurement_values", tags=["Quality Control"])
async def update_measurement_values(detailed_value: UpdateMeasurementValueModel, token: str = Depends(oauth2_scheme)):
    try:
        if token:
            now = datetime.now()
            find_records = quality_records_collection.find(
                {"project_id": detailed_value.project_id, "unit_name": detailed_value.unit_name,
                 "measurement_area": detailed_value.measurement_area,
                 "measurement_paramter": detailed_value.measurement_paramter}, {"_id": 0})
            find_records_list = await find_records.to_list(None)
            print(find_records_list)

            if len(find_records_list) != 0:
                print("Record found")
                new_measurement_value = []
                new_measurement_value.append(
                    find_records_list[0]["measurment_value"][0])
                current_measrement_value = {
                    "date_time": now.strftime("%d-%m-%Y %H:%M:%S"),
                    "value": detailed_value.measurment_value
                }
                new_measurement_value.append(current_measrement_value)

                await quality_records_collection.find_one_and_update(
                    {"project_id": detailed_value.project_id, "unit_name": detailed_value.unit_name,
                     "measurement_area": detailed_value.measurement_area,
                     "measurement_paramter": detailed_value.measurement_paramter},
                    {"$set": {
                        "measurment_value": new_measurement_value
                    }}, upsert=True
                )
            else:
                print("Record not found")

                data = {
                    "_id": str(uuid.uuid4()),
                    "project_id": detailed_value.project_id,
                    "unit_name": detailed_value.unit_name,
                    "measurement_area": detailed_value.measurement_area,
                    "measurement_paramter": detailed_value.measurement_paramter,
                    "measurment_value": [
                        {"date_time": now.strftime("%d-%m-%Y %H:%M:%S"), "value": detailed_value.measurment_value}],
                    "date_time": now.strftime("%d-%m-%Y %H:%M:%S")

                }
                quality_records_collection.insert_one(data)

            return JSONResponse(status_code=status.HTTP_200_OK, content=jsonable_encoder({"status": "Updated"}))

    except Exception as e:
        print(e)
        response = dict()
        response["message"] = "Error" + str(e)
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content=jsonable_encoder(response))


@app.post("/api/get_measurement_details", tags=["Quality Control"])
async def get_measurement_details(details: GetMeasurementValueModel, token: str = Depends(oauth2_scheme)):
    try:
        if token:

            records = quality_records_collection.find(
                {"project_id": details.project_id, "unit_name": details.unit_name}, {"_id": 0})

            records_list = await records.to_list(None)

            unique_measurement_area = []
            for row in records_list:
                if row["measurement_area"] not in unique_measurement_area:
                    unique_measurement_area.append(row["measurement_area"])
            salt_content_before = []
            salt_content_after = []
            thickness_after = []
            thickness_before = []
            roughnes_after = []

            for row in records_list:
                for area in unique_measurement_area:
                    if row["measurement_area"] == area:
                        if row["measurement_paramter"] == "Salt Content(ppm before irradiation)":
                            salt_content_before.append(
                                row["measurment_value"][-1]["value"])
                        else:
                            if row["measurement_paramter"] == "Salt Content(ppm after irradiation)":
                                salt_content_after.append(
                                    row["measurment_value"][-1]["value"])
                            else:
                                if row["measurement_paramter"] == "Thickness(μm before irradiation)":
                                    thickness_before.append(
                                        row["measurment_value"][-1]["value"])
                                else:
                                    if row["measurement_paramter"] == "Thickness(μm after irradiation)":
                                        thickness_after.append(
                                            row["measurment_value"][-1]["value"])
                                    else:
                                        if row["measurement_paramter"] == "Roughness(μm after irradiation)":
                                            roughnes_after.append(
                                                row["measurment_value"][-1]["value"])

            data = {}

            i = 0
            data_list = []
            print(salt_content_before)
            for row in unique_measurement_area:

                data = {
                    "measurement_area": row,

                }
                if i >= len(salt_content_before):
                    data["salt_content_before"] = 0
                else:
                    data["salt_content_before"] = salt_content_before[i]
                if i >= len(salt_content_after):
                    data["salt_content_after"] = 0
                else:
                    data["salt_content_after"] = salt_content_after[i]
                if i >= len(thickness_before):
                    data["thickness_before"] = 0
                else:
                    data["thickness_before"] = thickness_before[i]
                if i >= len(thickness_after):
                    data["thickness_after"] = 0
                else:
                    data["thickness_after"] = thickness_after[i]
                if i >= len(roughnes_after):
                    data["roughnes_after"] = 0
                else:
                    data["roughnes_after"] = roughnes_after[i]

                i += 1

                data_list.append(data)

            print("data=", data_list)
            return data_list

    except Exception as e:
        print(e)
        response = dict()
        response["message"] = "Error while fetching data"
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content=jsonable_encoder(response))


@app.post("/api/update_edited_value", tags=["Quality Control"])
async def update_edited_value(edit_details: UpdateEditedValueModel, token: str = Depends(oauth2_scheme)):
    try:
        if token:
            now = datetime.now()
            for row in edit_details.updated_value:
                if row == "salt_content_before":
                    measuring_parameter = "Salt Content(ppm before irradiation)"
                else:
                    if row == "salt_content_after":
                        measuring_parameter = "Salt Content(ppm after irradiation)"
                    else:
                        if row == "thickness_before":
                            measuring_parameter = "Thickness(μm before irradiation)"
                        else:
                            if row == "thickness_after":
                                measuring_parameter = "Thickness(μm after irradiation)"
                            else:
                                measuring_parameter = "Roughness(μm after irradiation)"

                print(row)
                print(edit_details.updated_value[row])
                find_records = quality_records_collection.find(
                    {"project_id": edit_details.project_id, "unit_name": edit_details.unit_name,
                     "measurement_area": edit_details.measurement_area,
                     "measurement_paramter": measuring_parameter}, {"_id": 0})
                find_records_list = await find_records.to_list(None)
                if len(find_records_list) != 0:
                    # print(find_records_list)
                    new_measurement_value = []
                    new_measurement_value.append(
                        find_records_list[0]["measurment_value"][0])
                    current_measrement_value = {
                        "date_time": now.strftime("%d-%m-%Y %H:%M:%S"),
                        "value": edit_details.updated_value[row]
                    }
                    new_measurement_value.append(current_measrement_value)

                    await quality_records_collection.find_one_and_update(
                        {"project_id": edit_details.project_id, "unit_name": edit_details.unit_name,
                         "measurement_area": edit_details.measurement_area,
                         "measurement_paramter": measuring_parameter},
                        {"$set": {
                            "measurment_value": new_measurement_value
                        }}, upsert=True
                    )
                else:
                    print("Record not found")

                    data = {
                        "_id": str(uuid.uuid4()),
                        "project_id": edit_details.project_id,
                        "unit_name": edit_details.unit_name,
                        "measurement_area": edit_details.measurement_area,
                        "measurement_paramter": measuring_parameter,
                        "measurment_value": [
                            {"date_time": now.strftime("%d-%m-%Y %H:%M:%S"), "value": edit_details.updated_value[row]}],
                        "date_time": now.strftime("%d-%m-%Y %H:%M:%S")

                    }
                    quality_records_collection.insert_one(data)

            return JSONResponse(status_code=status.HTTP_200_OK, content=jsonable_encoder({"status": "Updated"}))

    except Exception as e:
        print(e)
        response = {"msg": "fail"}
        return response


@app.post("/api/update_deleted_value", tags=["Quality Control"])
async def update_deleted_value(delete_details: UpdateDeletedValueModel, token: str = Depends(oauth2_scheme)):
    try:
        if token:
            print(delete_details)
            no_of_deletion = quality_records_collection.delete_many({"project_id": delete_details.project_id,
                                                                     "unit_name": delete_details.unit_name,
                                                                     "measurement_area": delete_details.measurement_area
                                                                     })

            return JSONResponse(status_code=status.HTTP_200_OK, content=jsonable_encoder({"status": "Deleted"}))
    except Exception as e:
        print(e)
        response = dict()
        response["message"] = "Error" + str(e)
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content=jsonable_encoder(response))


@app.post('/api/scheme/construction/progress_management/add_work_content', tags=["Progress Management"])
async def add_work_content(content: AddWorkContent = Body(...), token: str = Depends(oauth2_scheme)) -> JSONResponse:
    try:
        if token:
            data = jsonable_encoder(content)

            data["_id"] = str(uuid.uuid4())
            # pp(data)

            updated_date = datetime.strptime(
                data["datetime"], '%Y-%m-%dT%H:%M')
            data["datetime"] = updated_date

            await construction_rate_coll.insert_one(data)
            get_data = await construction_rate_coll.find_one({'_id': data["_id"]})

            print("Data for: " + str(get_data["_id"]))

            return JSONResponse(status_code=status.HTTP_200_OK,
                                content=jsonable_encoder({"message": "Work Content Added Successfully!"}))

    except Exception as e:
        print(e)
        return JSONResponse(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                            content=jsonable_encoder({"message": "UNPROCESSABLE ENTITY"}))


@app.post('/api/scheme/construction/progress_management/update_work_content/{work_content_id}',
          tags=["Progress Management"])
async def update_work_content(work_content_id, update_content: UpdateWorkContent = Body(...),
                              token: str = Depends(oauth2_scheme)):
    try:
        if token:
            data = jsonable_encoder(update_content)

            # pp(data)

            updated_date = datetime.strptime(data["datetime"], '%Y-%m-%dT%H:%M')
            data["datetime"] = updated_date

            modified_data = await construction_rate_coll.update_one(
                {"_id": work_content_id}, {
                    "$set": {
                        "datetime": data["datetime"],
                        "work_location": data["work_location"],
                        "work_content": data["work_content"],
                        "memo": data["memo"]
                    }})

            print("Updated record for : " + str(modified_data.matched_count))

            return JSONResponse(status_code=status.HTTP_200_OK,
                                content=jsonable_encoder({"message": "Work Content Updated Successfully!"}))

    except Exception as e:
        print(e)
        return JSONResponse(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                            content=jsonable_encoder({"message": "UNPROCESSABLE ENTITY"}))


@app.get('/api/scheme/construction/work_content/{project_site_id}', tags=["Progress Management"])
async def get_work_content(project_site_id, token: str = Depends(oauth2_scheme)):
    try:
        if token:
            project_site_data = await project_site_details_collection.find_one(
                {'_id': project_site_id}, {
                    '_id': 1,
                    'cons_area': 1,
                    'work_content': 1,
                    'start_date_time': 1,
                    'end_date_time': 1
                }
            )

            # pp(project_site_data)

            # cons_rate_data = construction_rate_coll.find({}).count()
            # count_of_cons_progress = its_construction_progress.find({}).count()
            #
            # count_cons_rate = {
            #     "count_cons_rate": count_of_cons_rate
            # }
            #
            # count_cons_progress = {
            #     "count_cons_progress": count_of_cons_progress
            # }
            #
            # res[site_name].append(count_cons_rate)
            # res[site_name].append(count_cons_progress)
            #
            # pp(res[site_name])
            #
            # # all_data = []E
            # # for x in res:
            # #     # pp(x)
            # #     all_data.append(x)
            # return make_response(jsonify(res[site_name]))

            return JSONResponse(status_code=status.HTTP_200_OK,
                                content=jsonable_encoder(project_site_data))

    except Exception as e:
        print(e)
        response = dict()
        response["message"] = "Error" + str(e)
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content=jsonable_encoder(response))


@app.post('/api/scheme/construction/progress_management/get_progress_table_data', tags=["Progress Management"])
async def get_construction_progress_details(project_details: GetProjectDetails, token: str = Depends(oauth2_scheme)):
    try:
        if token:
            # Fetching date details from project_site_details_collection
            dates = project_site_details_collection.find({"_id": project_details.project_id},
                                                         {"_id": 0, "start_date_time": 1, "end_date_time": 1,
                                                          "cons_area": 1})
            dates_list = await dates.to_list(None)
            # print(dates_list)

            # Converting datetime to only date
            end_date_only_no_time = dates_list[0]["end_date_time"].date()
            start_date_only_no_time = dates_list[0]["start_date_time"].date()
            no_of_days = (int(str(end_date_only_no_time - start_date_only_no_time)[0]))
            cons_area = dates_list[0]["cons_area"]

            # Adding header data to list dynamically
            column_header = ["cons_area", "area", start_date_only_no_time]
            for i in range(1, no_of_days + 1):
                start_date_only_no_time += timedelta(days=1)
                column_header.append(start_date_only_no_time)

            find_records = construction_progress_coll_test.find(
                {"project_site_id": project_details.project_id, "unit_name": project_details.unit_name}, {"_id": 0})
            find_records_list = await find_records.to_list(None)
            if len(find_records_list) != 0:
                all_data = construction_progress_coll_test.find(
                    {"project_site_id": project_details.project_id, "unit_name": project_details.unit_name}, {"_id": 0})
                all_data_list = await all_data.to_list(None)

                required_data_list = []
                total_area = 0

                for row in all_data_list:
                    required_data_format = {
                        "date_only": row["datetime"][0:10],
                        "cons_area": row["work_location"],
                        "progress_rate": row["progress_rate"]

                    }

                    required_data_list.append(required_data_format)

                print(required_data_list)
                table_row = []
                datewise_row_sum = []

                date_header = column_header[2:]
                for row in cons_area:

                    data = {
                        "cons_area": row["cons_area"],
                        "area": row["value"]
                    }
                    total_area += 0 if row["value"] == '' else float(row["value"])
                    for date in date_header:
                        for item in required_data_list:
                            if item["date_only"] == str(date) and item["cons_area"] == row["cons_area"]:
                                data[str(date)] = item["progress_rate"]

                                break
                            else:
                                data[str(date)] = ''

                    table_row.append(data)
                # Below code to add the Total roww

                print("total_area", total_area)
                data = {
                    "cons_area": "Total",
                    "area": total_area
                }
                for date in date_header:
                    data[str(date)] = ''

                table_row.append(data)

                # Below code to add Construction Amount row

                data = {
                    "cons_area": '',
                    "area": "Construction Amount"

                }
                count = 0
                for date in date_header:
                    for row in table_row:
                        if row[str(date)] != '':
                            print((row[str(date)].split("%")[0]))
                            count += (int((row[str(date)].split("%")[0]))) * float(row['area']) / 100
                    print(count)
                    data[str(date)] = count
                    count = 0
                table_row.append(data)

                # Below code to add Total construction amount row
                data = {
                    "cons_area": '',
                    "area": "Total Construction Amount"

                }
                construction_amount_row = table_row[-1]
                print(construction_amount_row)
                count = 0
                for date in date_header:
                    count += construction_amount_row[str(date)]
                    data[str(date)] = count
                table_row.append(data)

                # Below code to add Construction progress row
                total_construction_amount_row = table_row[-1]
                data = {
                    "cons_area": '',
                    "area": "Construction Progress"

                }
                eod_percent = 0

                for date in date_header:
                    if total_area == 0:
                        # eod_percent = round((total_construction_amount_row[str(date)] / total_area) * 100)
                        data[str(date)] = "Error"
                    else:
                        eod_percent = round((total_construction_amount_row[str(date)] / total_area) * 100)
                        data[str(date)] = str(eod_percent) + "%"

                table_row.append(data)

                return_data = {
                    "column_header": column_header,
                    "table_data": table_row
                }
                return return_data
            else:
                return_data = {
                    "column_header": column_header,
                    "table_data": []
                }
                return return_data

    except Exception as e:
        print(e)
        response = dict()
        response["message"] = "Error Fetching Data"
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content=jsonable_encoder(response))


@app.post('/api/scheme/construction/progress_management/construction_progress_update', tags=["Progress Management"])
async def construction_progress_update(update_content: ConstructionProgress = Body(...),
                                       token: str = Depends(oauth2_scheme)):
    try:
        if token:
            print(update_content.datetime[0:10])

            data = {
                "_id": str(uuid.uuid4()),
                "datetime": update_content.datetime[0:10],
                "work_location": update_content.work_location,
                "progress_rate": update_content.progress_rate,
                "project_site_id": update_content.project_site_id,
                "unit_name": update_content.unit_name

            }

            # Fectching date details from project_site_details_collection
            dates = project_site_details_collection.find({"_id": update_content.project_site_id},
                                                         {"_id": 0, "start_date_time": 1, "end_date_time": 1,
                                                          "cons_area": 1})
            dates_list = await dates.to_list(None)

            # Converting datetime to only date
            end_date_only_no_time = dates_list[0]["end_date_time"].date()
            start_date_only_no_time = dates_list[0]["start_date_time"].date()
            no_of_days = (int(str(end_date_only_no_time - start_date_only_no_time)[0]))
            cons_area = dates_list[0]["cons_area"]

            # Adding header data to list dynamically
            column_header = ["cons_area", "area", start_date_only_no_time]
            for i in range(1, no_of_days + 1):
                start_date_only_no_time += timedelta(days=1)
                column_header.append(start_date_only_no_time)

            # Checking weather the reords found or not corresponding updation or insertion is done
            find_records = construction_progress_coll_test.find(
                {"project_site_id": update_content.project_site_id, "unit_name": update_content.unit_name,
                 "work_location": update_content.work_location, "datetime": update_content.datetime[0:10]}, {"_id": 0})
            find_records_list = await find_records.to_list(None)
            if len(find_records_list) != 0:
                await construction_progress_coll_test.find_one_and_update(
                    {"project_site_id": update_content.project_site_id,
                     "unit_name": update_content.unit_name,
                     "work_location": update_content.work_location,
                     "datetime": update_content.datetime[0:10]
                     },

                    {"$set": {
                        "progress_rate": update_content.progress_rate
                    }}, upsert=True
                )
            else:
                construction_progress_coll_test.insert_one(data)

            return {"msg": "Updated Successfully"}

    except Exception as e:
        print(e)
        response = dict()
        response["message"] = "Could not update data"
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content=jsonable_encoder(response))


@app.get('/api/scheme/construction/construction_progress_data/{project_site_id}/{unit_name}',
         tags=["Progress Management"])
async def construction_rate_table(project_site_id, unit_name, token: str = Depends(oauth2_scheme)):
    try:
        if token:
            result = construction_progress_coll.find(
                {
                    "project_site_id": project_site_id,
                    "unit_name": unit_name
                }).sort('datetime', -1).limit(10)

            construction_rate_list = await result.to_list(None)

            # pp(construction_rate_list)

            res_list = []

            for items in construction_rate_list:
                pp(items)
                items["progress_rate"] = items["progress_rate"][-1]
                pp(items)
                res_list.append(items)

            return JSONResponse(status_code=status.HTTP_200_OK, content=jsonable_encoder(res_list))

    except Exception as e:
        print(e)
        response = dict()
        response["message"] = "Error Fetching Data"
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content=jsonable_encoder(response))


@app.get('/api/scheme/construction/construction_rate_data/{project_site_id}/{unit_name}', tags=["Progress Management"])
async def construction_rate_table(project_site_id, unit_name, token: str = Depends(oauth2_scheme)):
    try:
        if token:
            result = construction_rate_coll.find(
                {
                    "project_site_id": project_site_id,
                    "unit_name": unit_name
                }).sort('datetime', -1).limit(10)

            construction_rate_list = await result.to_list(None)

            # pp(construction_rate_list)

            return JSONResponse(status_code=status.HTTP_200_OK,
                                content=jsonable_encoder(construction_rate_list))
    except Exception as e:
        print(e)
        response = dict()
        response["message"] = "Error Fetching Data"
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content=jsonable_encoder(response))


@app.get('/api/scheme/construction/construction_rate_data/latest/{project_site_id}/{unit_name}',
         tags=["Progress Management"])
async def construction_rate_table(project_site_id, unit_name, token: str = Depends(oauth2_scheme)):
    try:
        if token:
            result = construction_rate_coll.find(
                {
                    "project_site_id": project_site_id,
                    "unit_name": unit_name
                }).sort('datetime', -1).limit(1)

            construction_rate_list = await result.to_list(None)

            # pp(construction_rate_list)

            for data in construction_rate_list:
                # pp(data)
                return JSONResponse(status_code=status.HTTP_200_OK, content=jsonable_encoder(data))

    except Exception as e:
        print(e)
        response = dict()
        response["message"] = "Error Fetching Data"
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content=jsonable_encoder(response))


@app.delete('/api/scheme/construction/construction_rate_data/delete/{cons_rate_table_id}', tags=["Progress Management"])
async def construction_rate_table(cons_rate_table_id, token: str = Depends(oauth2_scheme)):
    try:
        if token:
            result = await construction_rate_coll.delete_one({"_id": cons_rate_table_id})

            print(result.deleted_count)

            return JSONResponse(status_code=status.HTTP_200_OK,
                                content=jsonable_encoder({"message": "Deleted"}))

    except Exception as e:
        print(e)
        response = dict()
        response["message"] = "Error Deleting Data"
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content=jsonable_encoder(response))


@app.get("/api/scheme/construction/progress_management/work_record/{project_site_id}", tags=["Progress Management"])
async def work_record(project_site_id, token: str = Depends(oauth2_scheme)):
    try:
        if token:

            def get_column_record_with_location(title, field):
                return {"title": title, "field": field}

            work_content = ["機材搬入", "作業準備", "照射作業", "段取替え", "休憩", "消耗品交換", "システムエラー", "片付け", "機材搬出", "その他"]

            columns_work_record = []
            data_work_record = []

            project_start_end_date = await project_site_details_collection.find_one(
                {"_id": project_site_id},
                {"_id": 0, "start_date_time": 1, "end_date_time": 1, "cons_area": 1})

            project_locations = [project_start_end_date["cons_area"][i]["cons_area"] for i, area
                                 in enumerate(project_start_end_date["cons_area"])]
            # pp(project_locations)

            # fetch only date from datetime
            start_date_string = project_start_end_date["start_date_time"].strftime("%Y-%m-%d")
            end_date_string = project_start_end_date["end_date_time"].strftime("%Y-%m-%d")

            # convert to datetime format from string for only date
            start = datetime.strptime(start_date_string, "%Y-%m-%d")
            end = datetime.strptime(end_date_string, "%Y-%m-%d")

            # generate list of dates from start to end of the project
            date_generated = [start + timedelta(days=x) for x in range(0, (end - start).days + 1)]

            date_list = []
            for dates in date_generated:
                date_list.append(dates.strftime("%Y-%m-%d"))  # convert all dates to string format

            # print(date_list)

            # fetch all construction work content
            res = construction_rate_coll.find({}).sort("datetime", -1)
            data_list = await res.to_list(None)
            group_data = {}
            for loc in project_locations:
                res = construction_rate_coll.find({"work_location": loc}).sort("datetime", -1)
                data_list = await res.to_list(None)

                # group according to date for each data in dict

                group_data_nested = {}
                group_data_list = []  # [PJ1, PJ2]

                for index, data in enumerate(data_list):
                    if data["datetime"].strftime("%Y-%m-%d") in date_list:
                        if data["datetime"].strftime("%Y-%m-%d") in list(group_data_nested.keys()):
                            group_data_list.append(data)
                        else:
                            group_data_list = [data]  # list literal method (no need to initialize to empty and append)

                    group_data_nested[data["datetime"].strftime("%Y-%m-%d")] = group_data_list

                group_data[loc] = group_data_nested

            # pp(group_data)

            new_dict = {}
            new_list = []
            # Getting the difference of hours and minutes for each work content
            for key, value in group_data.items():
                for date_key, date_value in value.items():
                    for index, date_time in enumerate(date_value):
                        try:
                            print("-------------------------------------------")
                            # print(key, date_key)
                            new_dict[key] = columns_work_record.append(get_column_record_with_location(date_key, date_key))


                            # print("Content time - ", date_time["work_content"], date_time["datetime"])
                            # print("Another Content time - ", date_value[index + 1]["work_content"],
                            #       date_value[index + 1]["datetime"])
                            # print(date_time["datetime"] - date_value[index + 1]["datetime"])
                            print("-------------------------------------------")

                        except IndexError as e:
                            # print(e)
                            pass
            pp(columns_work_record)

            return JSONResponse(status_code=status.HTTP_200_OK,
                                content=jsonable_encoder({"message": "Data fetched", "data": group_data}))

    except Exception as e:
        traceback.print_exc()
        print(e)
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST,
                            content=jsonable_encoder({"message": "Couldn't fetch data!"}))


@app.post('/api/scheme/construction/system_state/laser_time/add', tags=["System Administrator"])
async def add_laser_time(new_content: AddLaserData = Body(...), token: str = Depends(oauth2_scheme)):
    try:
        if token:
            data = jsonable_encoder(new_content)
            data["_id"] = str(uuid.uuid4())

            updated_date = datetime.strptime(
                data["datetime"], '%Y-%m-%dT%H:%M:%S')
            data["datetime"] = updated_date
            res = await laser_data_coll.insert_one(data)
            print("Added records for ID no: " + str(res.inserted_id))

            return JSONResponse(status_code=status.HTTP_201_CREATED,
                                content=jsonable_encoder({"message": "New Data Added!"}))

    except Exception as e:
        traceback.print_exc()
        print(e)
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST,
                            content=jsonable_encoder({"message": "Couldn't Add data!"}))


@app.get('/api/scheme/construction/system_state/laser_time_table/{unit_name}', tags=["System Administrator"])
async def laser_data_table(unit_name, token: str = Depends(oauth2_scheme)):
    try:
        if token:
            result = laser_data_coll.find(
                {"unit_name": unit_name}).sort('datetime', -1).limit(10)
            its_laser_data_list = await result.to_list(None)

            return JSONResponse(status_code=status.HTTP_200_OK, content=jsonable_encoder(its_laser_data_list))

    except Exception as e:
        print(e)
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST,
                            content=jsonable_encoder({"message": "Couldn't Fetch data!"}))


@app.post('/api/scheme/feedback', tags=["Feedback"])
async def get_feedback(feedback_content: GetFeedback = Body(...), token: str = Depends(oauth2_scheme)):
    try:
        if token:
            data = jsonable_encoder(feedback_content)
            data["_id"] = str(uuid.uuid4())

            await feedbacks_coll.insert_one(data)
            get_data = await feedbacks_coll.find_one({'_id': data["_id"]})

            return JSONResponse(status_code=status.HTTP_200_OK,
                                content=jsonable_encoder({"message": "Data saved", "data": get_data}))
    except Exception as e:
        print(e)
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST,
                            content=jsonable_encoder({"message": "Couldn't save feedback"}))
