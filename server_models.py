from typing import List, Optional

import motor.motor_asyncio
from decouple import config
from pydantic import BaseModel, EmailStr, Field


class Connect(object):
    @staticmethod
    def get_connection():
        mongo_url = config("DB_URL")
        client = motor.motor_asyncio.AsyncIOMotorClient(mongo_url)
        return client


class ResetEmailSchema(BaseModel):
    email: List[EmailStr]


class ResetPasswordSchema(BaseModel):
    password_one: str
    confirm_password: str


class LoginResponseSchema(BaseModel):
    access_token: str
    token_type: str
    name: str
    email: str
    role: str


class User(BaseModel):
    username: str
    full_name: Optional[str] = None
    disabled: Optional[bool] = None


class LoginInputDataModel(BaseModel):
    username: str
    password: str


class ConstructionAreaList(BaseModel):
    cons_area: str
    value: str


class AreaList(BaseModel):
    area: str


class UpdateMeasurementValueModel(BaseModel):
    project_id: str
    unit_name: str
    measurement_area: str
    measurement_paramter: str
    measurment_value: str


class GetMeasurementValueModel(BaseModel):
    project_id: str
    unit_name: str


class RegisterProjectSiteDetails(BaseModel):
    id: str
    project_name: str
    start_date_time: str
    end_date_time: str
    select_units: list
    area: List[AreaList]
    cons_area: List[ConstructionAreaList]


class UpdateProjectSiteDetails(BaseModel):
    project_name: Optional[str]
    start_date_time: Optional[str]
    end_date_time: Optional[str]
    select_units: list
    area: List[AreaList]
    cons_area: List[ConstructionAreaList]



class AddWorkContent(BaseModel):
    id: Optional[str] = Field(alias="_id")
    datetime: str = Field(...)
    work_location: str = Field(...)
    work_content: str = Field(...)
    project_site_id: str = Field(...)
    unit_name: str = Field(...)
    memo: Optional[str]

    class Config:
        arbitrary_types_allowed = True
        schema_extra = {
            "example": {
                "_id": "id",
                "datetime": "start_date_time",
                "work_location": "work_location",
                "work_content": "work_content",
                "project_site_id": "project_site_id",
                "unit_name": "unit_name",
                "memo": "memo"
            }
        }


class UpdateWorkContent(BaseModel):
    id: Optional[str] = Field(alias="_id")
    datetime: str = Field(...)
    work_location: str = Field(...)
    work_content: str = Field(...)
    project_site_id: str = Field(...)
    unit_name: str = Field(...)
    memo: Optional[str]

    class Config:
        arbitrary_types_allowed = True
        schema_extra = {
            "example": {
                "_id": "id",
                "datetime": "start_date_time",
                "work_location": "work_location",
                "work_content": "work_content",
                "project_site_id": "project_site_id",
                "unit_name": "unit_name",
                "memo": "memo"
            }
        }


class ConstructionProgress(BaseModel):
    datetime: str = Field(...)
    work_location: str = Field(...)
    progress_rate: str = Field(...)
    project_site_id: str = Field(...)
    unit_name: str = Field(...)

    class Config:
        arbitrary_types_allowed = True
        schema_extra = {
            "example": {
                "_id": "id",
                "datetime": "start_date_time_today",
                "work_location": "work_location_today",
                "project_site_id": "project_site_id",
                "progress_rate": "progress_rate",
                "work_value": "work value",
                "unit_name": "unit_name"
            }
        }


class AddLaserData(BaseModel):
    id: Optional[str] = Field(alias="_id")
    datetime: str = Field(...)
    laser_time: str = Field(...)
    project_site_id: str = Field(...)
    unit_name: str = Field(...)

    class Config:
        arbitrary_types_allowed = True
        schema_extra = {
            "example": {
                "_id": "id",
                "datetime": "start_date_time",
                "laser_time": "parseInt(laser_time)",
                "project_site_id": "site_name",
                "unit_name": "unit_name"
            }
        }


class UpdateSystemState(BaseModel):
    datetime: str = Field(...)
    generator_status: bool = Field(...)
    air_status: bool = Field(...)
    error_memo: str = Field(...)
    error_status: bool = Field(...)
    key_switch: bool = Field(...)
    unit_name: str = Field(...)
    project_site_id: str = Field(...)

    class Config:
        arbitrary_types_allowed = True
        schema_extra = {
            "example": {
                'air_status': "air_status",
                'datetime': "new Date()",
                'generator_status': "generator_status",
                'error_memo': "error_memo",
                'error_status': "error_status",
                "project_site_id": "nikhil_project",
                'key_switch': "key_switch",
                'unit_name': "unit_name"
            }
        }


class UpdateEditedValueModel(BaseModel):
    project_id: str
    unit_name: str
    measurement_area: str
    updated_value: dict


class UpdateDeletedValueModel(BaseModel):
    project_id: str
    unit_name: str
    measurement_area: str


class GetProjectDetails(BaseModel):
    project_id: str
    unit_name: str


class GetFeedback(BaseModel):
    id: Optional[str] = Field(alias="_id")
    user_id: str
    experience: str
    suggestion: Optional[str]