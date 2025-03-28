import os
import logging
import time
from fastapi import FastAPI, Request, status, HTTPException, Depends
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from supabase import create_client, Client
import traceback
from pydantic import BaseModel, EmailStr
import aiohttp
import random
from nltk.chat.util import Chat, reflections
from typing import List
import json

logger = logging.getLogger()
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


def get_traceback(error):
    etype = type(error)
    trace = error.__traceback__
    lines = traceback.format_exception(etype, error, trace)
    return "".join(lines)


app = FastAPI()

# Allow requests from "/", "/chatbot", "/fetchOpenRoute", "/register", "/login"
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://carbapradah.vercel.app"],
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods (GET, POST, etc.)
    allow_headers=["*"],  # Allow all headers
)

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
API_KEY = "5b3ce3597851110001cf6248cef4ed4d3ac34da0acc6360e7bd2360f"
patterns = [
    (
        r"hi|hello|hey",
        [
            "Hey there! I'm your Carbon Emission Tracker Assistant. How can I help you today?"
        ],
    ),
    (
        r"who are you",
        [
            "I'm your smart assistant here to help you track and reduce carbon emissions! I can provide real-time data, eco-friendly routes, and insights on your emissions."
        ],
    ),
    (
        r"what can you do",
        [
            "I can:\n✅ Check your emission levels from MQ135 sensors\n✅ Help set thresholds and send alerts\n✅ Find the most carbon-efficient travel route\n✅ Show weekly/monthly stats\n✅ Give eco-friendly tips\n\nHow can I assist you today?"
        ],
    ),
    (
        r"what field do you want data from",
        [
            "I can help with:\n1️⃣ Agriculture → Track farm emissions & get reduction tips\n2️⃣ Transport → Analyze your travel emissions & suggest greener routes\n3️⃣ General stats → View your carbon footprint trends\n\nWhich one are you interested in?"
        ],
    ),
    (
        r"i want data from transport",
        [
            "🚗 Checking emissions from your travel history…\n📌 Total CO₂ from transport: [X] kg this week\n📌 Most eco-friendly route: [Route A / Route B]\n\nWant me to suggest a greener travel alternative?"
        ],
    ),
]


class CustomChat(Chat):
    def respond(self, str):
        """
        Generate a response to the user input.

        :type str: str
        :param str: The string to be mapped
        :rtype: str
        """

        # check each pattern
        for pattern, response in self._pairs:
            match = pattern.search(str)

            # did the pattern match?
            if match:
                resp = random.choice(response)  # pick a random response
                resp = self._wildcards(resp, match)  # process wildcards

                # fix munged punctuation at the end
                if resp[-2:] == "?.":
                    resp = resp[:-2] + "."
                if resp[-2:] == "??":
                    resp = resp[:-2] + "?"
                return resp


# Pydantic Models
class RegisterData(BaseModel):
    email: EmailStr
    password: str
    username: str


class LoginData(BaseModel):
    email: EmailStr
    password: str


class SensorsData(BaseModel):
    sensor_value: int
    voltage: float
    co2: float
    ch4: float
    voc: float
    digital_state: int
    mac_address: str


class TransportData(BaseModel):
    distance: float
    carbon_emitted: float
    mac_address: str


class ChatbotData(BaseModel):
    user_input: str


class CoordinatesRequest(BaseModel):
    coordinates: List[List[float]]


chatbot = CustomChat(pairs=patterns, reflections=reflections)

AUTH_TOKEN = "hoFG9memOPLOI4ENcOy9f8nIIozcY20r97oNbICUYNyiGGhdag"


def check_auth(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized")

    token = auth_header.split("Bearer ")[1]
    if token != AUTH_TOKEN:
        raise HTTPException(status_code=403, detail="Forbidden: Invalid token")


@app.post("/postSensorsData")
async def postSensorsData(
    request: Request, data: SensorsData, auth: None = Depends(check_auth)
):

    try:
        # fetch user_id from sensormac table(macaddress text, userid text)
        result = (
            supabase.table("sensormac")
            .select("userid")
            .eq("macaddress", str(data.mac_address))
            .execute()
        )
        user_id = result.data[0]["userid"]
        if not user_id:
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={"error": "User not found"},
            )
        user = (
            supabase.table("agriculture")
            .insert(
                [
                    {
                        "co2": data.co2,
                        "ch4": data.ch4,
                        "voc": data.voc,
                        "timestamp": int(time.time()),
                        "userid": user_id,
                    }
                ]
            )
            .execute()
        )
        if user:
            return JSONResponse(
                status_code=status.HTTP_201_CREATED,
                content={"message": "Data posted successfully"},
            )
    except Exception as e:
        logger.error(f"Error posting data: {get_traceback(e)}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": "Data posting failed"},
        )


@app.post("/postTransportData")
async def postTransportData(
    request: Request, data: TransportData, auth: None = Depends(check_auth)
):

    try:
        user = (
            supabase.table("transport")
            .insert(
                [
                    {
                        "distance": data.distance,
                        "carbonemitted": data.carbon_emitted,
                        "timestamp": int(time.time()),
                        "macaddress": data.mac_address,
                    }
                ]
            )
            .execute()
        )
        if user:
            return JSONResponse(
                status_code=status.HTTP_201_CREATED,
                content={"message": "Data posted successfully"},
            )
    except Exception as e:
        logger.error(f"Error posting data: {get_traceback(e)}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": "Data posting failed"},
        )


@app.post("/fetchOpenRoute")
async def fetchOpenRoute(request: Request, data: CoordinatesRequest):
    try:
        new_headers = {}
        new_headers["Authorization"] = f"Bearer {API_KEY}"
        async with aiohttp.ClientSession() as session:
            async with session.post(
                "https://api.openrouteservice.org/v2/directions/driving-car/geojson",
                json=json.loads(data.model_dump_json()),  # Use json instead of data
                headers=new_headers,
            ) as response:
                print(f"URL: {response.url}")
                print(f"Request Body: {data.model_dump_json()}")
                print(f"Request Headers: {new_headers}")
                print(f"Status: {response.status}")
                body = await response.json()
                print(f"Body: {body}")

                return body

    except Exception as e:
        logger.error(f"Error fetching data: {get_traceback(e)}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": "Data fetching failed"},
        )


@app.post("/getChatbotResponse")
async def getChatbotResponse(request: Request, data: ChatbotData):
    user_input = data.user_input
    resp = chatbot.respond(user_input)
    if not resp:
        resp = "Sorry, I don't understand. Please try again."
    return JSONResponse(
        status_code=status.HTTP_200_OK, content={"status": "ok", "response": resp}
    )


@app.post("/register")
async def register(request: Request, data: RegisterData):
    if len(data.password) < 6:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": "Password must be at least 6 characters long"},
        )

    try:
        # Check if user already exists
        existing_user = supabase.auth.sign_in_with_password(
            {"email": data.email, "password": data.password}
        )
        print(existing_user.user)
        if existing_user:
            return JSONResponse(
                status_code=status.HTTP_409_CONFLICT,
                content={"error": "User already exists"},
            )
    except Exception:
        pass  # User does not exist, proceed to create

    try:
        # Create user
        user = supabase.auth.sign_up({"email": data.email, "password": data.password})
        if user:
            return JSONResponse(
                status_code=status.HTTP_201_CREATED,
                content={"message": "User registered successfully"},
            )
    except Exception as e:
        logger.error(f"Error registering user: {get_traceback(e)}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": "Registration failed"},
        )


@app.post("/login")
async def login(request: Request, data: LoginData):
    try:
        user = supabase.auth.sign_in_with_password(
            {"email": data.email, "password": data.password}
        )
        print(user.user)
        if user:
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content={
                    "access_token": user.session.access_token,
                    "refresh_token": user.session.refresh_token,
                    "expires_at": user.session.expires_at,
                },
            )
        else:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"error": "Invalid email or password"},
            )

    except Exception as e:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"error": str(e)},
        )
