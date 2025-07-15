# from fastapi import FastAPI, Header, HTTPException
# from fastapi.middleware.cors import CORSMiddleware
# import requests

# app = FastAPI()

# # ✅ Allow your React app to call FastAPI
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"],  # For production, restrict this to your frontend domain
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

# GRAPH_BASE = "https://graph.microsoft.com/v1.0"

# @app.post("/process-user")
# def process_user(authorization: str = Header(...)):
#     # ✅ Check for Bearer token
#     if not authorization.startswith("Bearer "):
#         raise HTTPException(status_code=401, detail="Invalid Authorization header")

#     access_token = authorization.split(" ")[1]
#     headers = {
#         "Authorization": f"Bearer {access_token}",
#         "Accept": "application/json"
#     }

#     # ✅ Get user profile
#     user_res = requests.get(f"{GRAPH_BASE}/me", headers=headers)
#     if user_res.status_code != 200:
#         raise HTTPException(status_code=user_res.status_code, detail="Failed to fetch user profile")
#     user_info = user_res.json()
#     user_email = user_info.get("mail") or user_info.get("userPrincipalName")

#     # ✅ Get top 10 recent emails
#     emails_res = requests.get(f"{GRAPH_BASE}/me/messages?$top=10", headers=headers)
#     if emails_res.status_code != 200:
#         raise HTTPException(status_code=emails_res.status_code, detail="Failed to fetch emails")
#     emails = emails_res.json().get("value", [])

#     # ✅ Return user + email data
#     return {
#         "user": {
#             "email": user_email,
#             "name": user_info.get("displayName"),
#         },
#         "emails": emails
#     }

# from fastapi import FastAPI, Header, HTTPException
# from fastapi.middleware.cors import CORSMiddleware
# import requests
# from datetime import datetime, timedelta
# import uuid

# app = FastAPI()

# # CORS (for local React app)
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

# GRAPH_BASE = "https://graph.microsoft.com/v1.0"
# subscribed_users = {}  # Temp storage – replace with Supabase later

# def subscribe_user_to_emails(token: str, user_email: str):
#     if user_email in subscribed_users:
#         print(f"User {user_email} already subscribed.")
#         return

#     expiration_time = (datetime.utcnow() + timedelta(hours=1)).isoformat() + "Z"
#     subscription_payload = {
#         "changeType": "created",
        
#         "notificationUrl": "https://venkatasaibhargav.app.n8n.cloud/webhook-test/process-new-email",


#         "resource": "me/mailFolders('Inbox')/messages",
#         "expirationDateTime": expiration_time,
#         "clientState": str(uuid.uuid4())
#     }

#     headers = {
#         "Authorization": f"Bearer {token}",
#         "Content-Type": "application/json"
#     }

#     res = requests.post(f"{GRAPH_BASE}/subscriptions", headers=headers, json=subscription_payload)

#     if res.status_code == 201:
#         sub_id = res.json().get("id")
#         subscribed_users[user_email] = {
#             "subscription_id": sub_id,
#             "expires": expiration_time
#         }
#         print(f"✅ Subscribed {user_email} to email notifications.")
#     else:
#         print("❌ Subscription failed:", res.text)
#         raise HTTPException(status_code=500, detail="Could not subscribe user.")

# @app.post("/process-user")
# def process_user(authorization: str = Header(...)):
#     if not authorization.startswith("Bearer "):
#         raise HTTPException(status_code=401, detail="Invalid authorization header")

#     token = authorization.split(" ")[1]
#     headers = {"Authorization": f"Bearer {token}"}

#     # Get user profile
#     user_profile = requests.get(f"{GRAPH_BASE}/me", headers=headers)
#     if user_profile.status_code != 200:
#         raise HTTPException(status_code=403, detail="Unable to fetch user profile")
    
#     user_data = user_profile.json()
#     user_email = user_data.get("mail") or user_data.get("userPrincipalName")

#     # Subscribe them
#     subscribe_user_to_emails(token, user_email)

#     return {
#         "message": f"✅ {user_email} is now subscribed to email notifications.",
#         "expires_at": subscribed_users[user_email]["expires"]
#     }

# from fastapi import FastAPI, Header, HTTPException, Request
# from fastapi.middleware.cors import CORSMiddleware
# from fastapi.responses import PlainTextResponse
# import requests
# from datetime import datetime, timedelta, timezone
# import uuid
# import json

# app = FastAPI()

# # CORS Configuration
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

# GRAPH_BASE = "https://graph.microsoft.com/v1.0"
# subscribed_users = {}  # In-memory storage (replace with database later)

# def subscribe_user_to_emails(token: str, user_email: str):
#     if user_email in subscribed_users:
#         print(f"User {user_email} already subscribed.")
#         return subscribed_users[user_email]

#     client_state = str(uuid.uuid4())
#     expiration_time = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    
#     subscription_payload = {
#         "changeType": "created",
#         "notificationUrl": "https://venkatasaibhargav.app.n8n.cloud/webhook/process-new-email",
#         "resource": "me/mailFolders('Inbox')/messages",
#         "expirationDateTime": expiration_time,
#         "clientState": client_state  # Crucial for security validation
#     }

#     headers = {
#         "Authorization": f"Bearer {token}",
#         "Content-Type": "application/json"
#     }

#     try:
#         res = requests.post(
#             f"{GRAPH_BASE}/subscriptions",
#             headers=headers,
#             json=subscription_payload,
#             timeout=10
#         )
#         res.raise_for_status()

#         sub_data = res.json()
#         subscribed_users[user_email] = {
#             "subscription_id": sub_data.get("id"),
#             "expires": expiration_time,
#             "client_state": client_state,
#             "token": token  # Store token for renewal
#         }
#         print(f"✅ Subscribed {user_email}. ID: {sub_data.get('id')}")
#         return subscribed_users[user_email]

#     except requests.exceptions.RequestException as e:
#         print(f"❌ Subscription failed: {str(e)}")
#         raise HTTPException(
#             status_code=500,
#             detail=f"Could not subscribe user: {str(e)}"
#         )

# @app.post("/process-user")
# async def process_user(authorization: str = Header(...)):
#     if not authorization.startswith("Bearer "):
#         raise HTTPException(status_code=401, detail="Invalid authorization header")

#     token = authorization[7:]  # Remove 'Bearer ' prefix
#     headers = {"Authorization": f"Bearer {token}"}

#     try:
#         # Get user profile
#         user_profile = requests.get(f"{GRAPH_BASE}/me", headers=headers)
#         user_profile.raise_for_status()
#         user_data = user_profile.json()
        
#         user_email = user_data.get("mail") or user_data.get("userPrincipalName")
#         if not user_email:
#             raise HTTPException(status_code=400, detail="No email found in profile")

#         # Subscribe user
#         subscription = subscribe_user_to_emails(token, user_email)
        
#         return {
#             "message": f"✅ {user_email} subscribed to email notifications",
#             "subscription_id": subscription["subscription_id"],
#             "expires_at": subscription["expires"],
#             "client_state": subscription["client_state"]
#         }

#     except requests.exceptions.RequestException as e:
#         raise HTTPException(status_code=502, detail=f"Microsoft Graph error: {str(e)}")

# # Critical Webhook Endpoint
# @app.post("/process-new-email")
# async def handle_notification(request: Request):
#     # Handle validation request (GET with validationToken)
#     if request.method == "GET" or "validationToken" in request.query_params:
#         token = request.query_params.get("validationToken")
#         if token:
#             return PlainTextResponse(content=token, media_type="text/plain")
    
#     # Handle actual notifications
#     try:
#         notification = await request.json()
#         print("Received notification:", json.dumps(notification, indent=2))
        
#         # Validate client state if needed
#         # (Compare against stored client_state in subscribed_users)
        
#         # Process notifications
#         for item in notification.get("value", []):
#             message_id = item.get("resourceData", {}).get("id")
#             if message_id:
#                 print(f"New email received with ID: {message_id}")
#                 # Add your processing logic here
        
#         return {"status": "success", "processed": len(notification.get("value", []))}
    
#     except Exception as e:
#         print(f"Notification processing error: {str(e)}")
#         raise HTTPException(status_code=400, detail=str(e))


# from fastapi import FastAPI, Header, HTTPException, Request
# from fastapi.middleware.cors import CORSMiddleware
# import requests
# from datetime import datetime, timedelta
# import uuid
# import json



# app = FastAPI()

# # CORS for frontend dev
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["http://localhost:5173"],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

# GRAPH_BASE = "https://graph.microsoft.com/v1.0"
# subscribed_users = {}  # Temporary storage

# # ----------------------------
# # Helper: Subscribe user
# # ----------------------------
# def subscribe_user_to_emails(token: str, user_email: str):
#     if user_email in subscribed_users:
#         return subscribed_users[user_email]

#     client_state = str(uuid.uuid4())
    
#     expiration_time = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    
#     subscription_payload = {
#         "changeType": "created",
#         "notificationUrl": "https://venkatasaibhargav.app.n8n.cloud/webhook/process-new-email",
#         "resource": "me/mailFolders('Inbox')/messages",
#         "expirationDateTime": expiration_time,
#         "clientState": client_state
#     }

#     headers = {
#         "Authorization": f"Bearer {token}",
#         "Content-Type": "application/json"
#     }

#     try:
#         res = requests.post(
#             f"{GRAPH_BASE}/subscriptions",
#             headers=headers,
#             json=subscription_payload,
#             timeout=10
#         )
#         res.raise_for_status()
#         sub_data = res.json()

#         # Store metadata for later processing
#         subscribed_users[user_email] = {
#             "subscription_id": sub_data.get("id"),
#             "expires": expiration_time,
#             "client_state": client_state,
#             "token": token  # Used later to fetch email content
#         }

#         print(f"✅ Subscribed {user_email} (ID: {sub_data.get('id')})")
#         return subscribed_users[user_email]

#     except requests.exceptions.RequestException as e:
#         # print(f"❌ Subscription error: {str(e)}")
#         # raise HTTPException(status_code=500, detail=str(e))
#         if e.response is not None:
#             print("❌ Graph Error Response:", e.response.text)
#     else:
#         print("❌ Request Exception:", str(e))
#     raise HTTPException(status_code=500, detail=str(e))


# # ----------------------------
# # Route 1: Trigger subscription
# # ----------------------------
# @app.post("/process-user")
# async def process_user(authorization: str = Header(...)):
#     if not authorization.startswith("Bearer "):
#         raise HTTPException(status_code=401, detail="Invalid auth header")

#     token = authorization[7:]
#     headers = {"Authorization": f"Bearer {token}"}

#     try:
#         user_profile = requests.get(f"{GRAPH_BASE}/me", headers=headers)
#         user_profile.raise_for_status()
#         user_data = user_profile.json()

#         user_email = user_data.get("mail") or user_data.get("userPrincipalName")
#         if not user_email:
#             raise HTTPException(status_code=400, detail="Email not found in profile")

#         subscription = subscribe_user_to_emails(token, user_email)

#         return {
#             "message": f"{user_email} subscribed to email notifications",
#             "subscription_id": subscription["subscription_id"],
#             "expires_at": subscription["expires"],
#             "client_state": subscription["client_state"]
#         }

#     except requests.exceptions.RequestException as e:
#         raise HTTPException(status_code=502, detail=f"Graph error: {str(e)}")


# # ----------------------------
# # Route 2 (Optional): Fetch full email
# # ----------------------------
# @app.post("/fetch-message")
# async def fetch_email_body(payload: dict):
#     message_id = payload.get("message_id")
#     subscription_id = payload.get("subscription_id")

#     if not message_id:
#         raise HTTPException(status_code=400, detail="Missing message_id")

#     # Find user with this subscription_id
#     matched_user = None
#     for email, data in subscribed_users.items():
#         if data["subscription_id"] == subscription_id:
#             matched_user = data
#             break

#     if not matched_user:
#         raise HTTPException(status_code=404, detail="Subscription not found")

#     token = matched_user["token"]
#     headers = {"Authorization": f"Bearer {token}"}

#     try:
#         res = requests.get(f"{GRAPH_BASE}/me/messages/{message_id}", headers=headers)
#         res.raise_for_status()
#         msg = res.json()

#         return {
#             "subject": msg.get("subject"),
#             "from": msg.get("from", {}).get("emailAddress", {}).get("address"),
#             "body_preview": msg.get("bodyPreview"),
#             "received": msg.get("receivedDateTime")
#         }

#     except requests.exceptions.RequestException as e:
#         raise HTTPException(status_code=500, detail=f"Email fetch error: {str(e)}")



from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
import requests
from datetime import datetime, timedelta, timezone
import uuid
import json
import httpx
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
import asyncio
from contextlib import asynccontextmanager
from dotenv import load_dotenv
from redis.asyncio import Redis

import os
load_dotenv()
redis = Redis.from_url(os.getenv("REDIS_URL"), decode_responses=True)
@asynccontextmanager
async def lifespan(app: FastAPI):
    scheduler.add_job(
        refresh_tokens_and_subscriptions,
        trigger=IntervalTrigger(minutes=6),
        name="refresh_tokens_every_6_minutes"
    )
    scheduler.start()
    print("🕒 Scheduler started.")
    yield
    scheduler.shutdown()

app = FastAPI(lifespan=lifespan)
scheduler = AsyncIOScheduler()

# Allow localhost frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173","http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
# subscribed_users = {}  # Replace with DB in production



# user_tokens = {}
# user_id_to_email = {}


 # Every 6 mins


async def refresh_tokens_and_subscriptions():
    print("🔁 Running scheduled refresh...")
    keys = await redis.keys("user_id:*")
    
    for user_id_key in keys:
        user_email = await redis.get(user_id_key)
        token_json = await redis.get(user_email)
        if not token_json:
            continue
        
        token_data = json.loads(token_json)
        now = datetime.now(timezone.utc)
        expires_at = datetime.fromisoformat(token_data["expires_at"])

        # Refresh if token is about to expire in next 10 mins
        if (expires_at - now).total_seconds() <= 600:
            try:
                async with httpx.AsyncClient() as client:
                    res = await client.post(
                        "https://login.microsoftonline.com/08423cbb-15b2-4cc9-a5a6-b7b2701a472b/oauth2/v2.0/token",
                        data={
                            "client_id": os.getenv("CLIENT_ID"),
                            "grant_type": "refresh_token",
                            "refresh_token": token_data["refresh_token"],
                            "scope": "User.Read Mail.Read offline_access",
                            "redirect_uri": os.getenv("REDIRECT_URI"),
                            "client_secret": os.getenv("CLIENT_SECRET"),
                        }
                    )
                    res.raise_for_status()
                    refreshed = res.json()

                    token_data["access_token"] = refreshed["access_token"]
                    token_data["refresh_token"] = refreshed.get("refresh_token", token_data["refresh_token"])
                    token_data["expires_at"] = (now + timedelta(seconds=refreshed["expires_in"])).isoformat()

                    await redis.set(user_email, json.dumps(token_data))

                    await subscribe_user_to_emails(token_data["access_token"], user_email)

                    print(f"✅ Refreshed and re-subscribed: {user_email}")
            except Exception as e:
                print(f"❌ Failed to refresh for {user_email}: {e}")

# Register job



@app.post("/auth/exchange")
async def exchange_code(payload: dict):
    code = payload.get("code")
    code_verifier = payload.get("code_verifier")

    if not code or not code_verifier:
        raise HTTPException(status_code=400, detail="Missing authorization code or code verifier")

    data = {
        "client_id": os.getenv("CLIENT_ID"),
        "scope": "User.Read Mail.Read offline_access",
        "code": code,
        "redirect_uri": os.getenv("REDIRECT_URI"),
        "grant_type": "authorization_code",
        "code_verifier": code_verifier,
        "client_secret": os.getenv("CLIENT_SECRET"),
    }

    try:
        async with httpx.AsyncClient() as client:
            # Exchange code for token
            res = await client.post(
                "https://login.microsoftonline.com/08423cbb-15b2-4cc9-a5a6-b7b2701a472b/oauth2/v2.0/token",
                data=data
            )
            res.raise_for_status()
            token_data = res.json()

            access_token = token_data["access_token"]
            refresh_token = token_data["refresh_token"]
            expires_in = token_data["expires_in"]
            expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)

            # Get user info
            profile_res = await client.get(
                f"{GRAPH_BASE}/me",
                headers={"Authorization": f"Bearer {access_token}"}
            )
            profile_res.raise_for_status()
            user_data = profile_res.json()

    except httpx.HTTPStatusError as e:
        print("❌ Token exchange failed:", e.response.text)
        raise HTTPException(status_code=e.response.status_code, detail="Token exchange failed")

    except Exception as e:
        print("❌ General error during token exchange:", str(e))
        raise HTTPException(status_code=500, detail="Unexpected error")

    # Extract user identity
    user_email = user_data.get("mail") or user_data.get("userPrincipalName")
    user_id = user_data.get("id")

    if not user_email:
        raise HTTPException(status_code=400, detail="Could not extract user email")
    if not user_id:
        raise HTTPException(status_code=400, detail="Could not extract user ID")

    # Save email lookup
    await redis.set(f"user_id:{user_id}", user_email)

    # Save token info in Redis
    await redis.set(user_email, json.dumps({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_at": expires_at.isoformat()
    }))

    return {
        "message": f"{user_email} authorized",
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_in": expires_in
    }



@app.get("/debug/tokens")
async def debug():
    keys = await redis.keys("token:*")
    return {key: await redis.get(key) for key in keys}



# @app.get("/get-token")
# def get_token(user_email: str):
#     token_data = user_tokens.get(user_email)
#     if not token_data:
#         raise HTTPException(status_code=404, detail="User not authorized")
#     return {"access_token": token_data["access_token"]}


# 


# ----------------------------
# Subscribe a user to email notifications
# ----------------------------
async def subscribe_user_to_emails(token: str, user_email: str):
    redis_key = f"subscription:{user_email}"
    existing_sub = await redis.get(redis_key)

    if existing_sub:
        sub_data = json.loads(existing_sub)
        expires_at = datetime.fromisoformat(sub_data["expires"]).replace(tzinfo=timezone.utc)

        if expires_at > datetime.now(timezone.utc):
            print(f"⚠️ User {user_email} already has an active subscription.")
            return sub_data

    client_state = str(uuid.uuid4())
    expiration_time = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")

    subscription_payload = {
        "changeType": "created",
        "notificationUrl": "https://venkatasaibhargav.app.n8n.cloud/webhook/process-new-email",
        "resource": "me/mailFolders('Inbox')/messages",
        "expirationDateTime": expiration_time,
        "clientState": client_state
    }

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    print(f"📡 Subscribing user {user_email} with expiration {expiration_time}")
    try:
        res = requests.post(f"{GRAPH_BASE}/subscriptions", headers=headers, json=subscription_payload, timeout=10)
        print("🔁 Graph subscription response:", res.text)
        res.raise_for_status()
        sub_data = res.json()

        subscription_info = {
            "subscription_id": sub_data.get("id"),
            "expires": datetime.strptime(sub_data.get("expirationDateTime"), "%Y-%m-%dT%H:%M:%SZ").isoformat(),
            "client_state": client_state,
            "token": token
        }

        await redis.set(redis_key, json.dumps(subscription_info))
        print(f"✅ Subscription successful: ID {sub_data.get('id')}")
        return subscription_info

    except requests.exceptions.RequestException as e:
        print(f"❌ Subscription failed: {e}")
        if e.response is not None:
            print("❌ Graph error body:", e.response.text)
        raise HTTPException(status_code=500, detail="Graph subscription failed")
    
@app.get("/get-email-and-token")
async def get_email_and_token(userId: str):
    redis_email = await redis.get(f"user_id:{userId}")
    if not redis_email:
        raise HTTPException(status_code=404, detail="Email not found for userId")
    user_email = redis_email

    token_json = await redis.get(user_email)
    if not token_json:
        raise HTTPException(status_code=404, detail="Token not found in Redis")

    token_data = json.loads(token_json)
    now = datetime.now(timezone.utc)
    expires_at = datetime.fromisoformat(token_data["expires_at"])

    if expires_at <= now:
        print(f"🔁 Token expired for {user_email}, refreshing...")

        data = {
            "client_id": os.getenv("CLIENT_ID"),
            "grant_type": "refresh_token",
            "refresh_token": token_data["refresh_token"],
            "scope": "User.Read Mail.Read offline_access",
            "redirect_uri": os.getenv("REDIRECT_URI"),
            "client_secret": os.getenv("CLIENT_SECRET"),
        }

        async with httpx.AsyncClient() as client:
            try:
                res = await client.post(
                    "https://login.microsoftonline.com/08423cbb-15b2-4cc9-a5a6-b7b2701a472b/oauth2/v2.0/token",
                    data=data
                )
                res.raise_for_status()
                refreshed = res.json()

                token_data["access_token"] = refreshed["access_token"]
                token_data["refresh_token"] = refreshed.get("refresh_token", token_data["refresh_token"])
                token_data["expires_at"] = (now + timedelta(seconds=refreshed["expires_in"])).isoformat()

                await redis.set(user_email, json.dumps(token_data))

                await subscribe_user_to_emails(token_data["access_token"], user_email)

                print(f"✅ Token refreshed for {user_email}")

            except Exception as e:
                print(f"❌ Refresh failed for {user_email}: {str(e)}")
                raise HTTPException(status_code=500, detail="Failed to refresh token")

    return {
        "user_email": user_email,
        "access_token": token_data["access_token"]
    }

# ----------------------------
# Step 1: Get token and profile
# ----------------------------
@app.post("/process-user")
async def process_user(authorization: str = Header(...)):
    print("🔐 Incoming authorization header:", authorization[:50], "...")

    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")

    token = authorization[7:]
    headers = {"Authorization": f"Bearer {token}"}

    try:
        res = requests.get(f"{GRAPH_BASE}/me", headers=headers)
        print("🧑 /me response:", res.text)
        res.raise_for_status()

        user_data = res.json()
        user_email = user_data.get("mail") or user_data.get("userPrincipalName")

        if not user_email:
            raise HTTPException(status_code=400, detail="Could not extract email from profile")

        subscription = await subscribe_user_to_emails(token, user_email)

        # return {
        #     "message": f"✅ {user_email} subscribed",
        #     "subscription_id": subscription["subscription_id"],
        #     "expires_at": subscription["expires"],
        #     "client_state": subscription["client_state"]
        # }
        return {
    "message": f"✅ {user_email} subscribed",
    "subscription_id": subscription["subscription_id"],
    "expires_at": subscription["expires"],
    "client_state": subscription["client_state"],
    "email": user_email,
    "name": user_data.get("displayName", "")  # 👈 Add displayName from /me
}


    except requests.exceptions.RequestException as e:
        print("❌ Graph error:", str(e))
        if e.response is not None:
            print("❌ Graph /me error body:", e.response.text)
        raise HTTPException(status_code=502, detail="Microsoft Graph error")








# @app.post("/store-token")
# def store_token(user_email: str, access_token: str, refresh_token: str):
#     user_tokens[user_email] = {
#         "access_token": access_token,
#         "refresh_token": refresh_token,
#         "expires_at": datetime.utcnow() + timedelta(minutes=60)  # basic TTL
#     }
#     return {"status": "stored"}



# @app.post("/auth/exchange")
# async def exchange_code(payload: dict):
#     code = payload.get("code")
#     if not code:
#         raise HTTPException(status_code=400, detail="Missing authorization code")

#     data = {
#         "client_id": "d73dfe28-c155-42a6-8145-445a0e795a19",
#         "scope": "User.Read Mail.Read offline_access",
#         "code": code,
#         "redirect_uri": "http://localhost:5173/redirect",
#         "grant_type": "authorization_code",
#         "client_secret": "IMG8Q~bKJKrXc14sNl_VSsEF4UTW4ly0LxVM4bgu",
#     }

#     async with httpx.AsyncClient() as client:
#         res = await client.post(
#             "https://login.microsoftonline.com/08423cbb-15b2-4cc9-a5a6-b7b2701a472b/oauth2/v2.0/token",
#             data=data
#         )
#         res.raise_for_status()
#         token_data = res.json()

#         access_token = token_data["access_token"]
#         refresh_token = token_data["refresh_token"]
#         expires_in = token_data["expires_in"]

#         # ✅ This should stay inside `async with`
#         profile_res = await client.get(
#             f"{GRAPH_BASE}/me",
#             headers={"Authorization": f"Bearer {access_token}"}
#         )
#         profile_res.raise_for_status()
#         user_data = profile_res.json()

#     # Now outside the `async with`
#     user_email = user_data.get("mail") or user_data.get("userPrincipalName")
#     if not user_email:
#         raise HTTPException(status_code=400, detail="Could not extract user email")

#     user_tokens[user_email] = {
#         "access_token": access_token,
#         "refresh_token": refresh_token,
#         "expires_at": datetime.now(timezone.utc) + timedelta(seconds=expires_in),
#     }

#     return {"message": f"{user_email} authorized"}



# def subscribe_user_to_emails(token: str, user_email: str):
#     if user_email in subscribed_users:
#         print(f"⚠️ User {user_email} already subscribed.")
#         return subscribed_users[user_email]

#     client_state = str(uuid.uuid4())
#     expiration_time = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")

#     subscription_payload = {
#         "changeType": "created",
#         "notificationUrl": "https://venkatasaibhargav.app.n8n.cloud/webhook/process-new-email",
#         "resource": "me/mailFolders('Inbox')/messages",
#         "expirationDateTime": expiration_time,
#         "clientState": client_state
#     }

#     headers = {
#         "Authorization": f"Bearer {token}",
#         "Content-Type": "application/json"
#     }

#     print(f"📡 Subscribing user {user_email} with expiration {expiration_time}")
#     try:
#         res = requests.post(f"{GRAPH_BASE}/subscriptions", headers=headers, json=subscription_payload, timeout=10)
#         print("🔁 Graph subscription response:", res.text)
#         res.raise_for_status()
#         sub_data = res.json()

#         subscribed_users[user_email] = {
#             "subscription_id": sub_data.get("id"),
#             "expires": expiration_time,
#             "client_state": client_state,
#             "token": token
#         }

#         print(f"✅ Subscription successful: ID {sub_data.get('id')}")
#         return subscribed_users[user_email]

#     except requests.exceptions.RequestException as e:
#         print(f"❌ Subscription failed: {e}")
#         if e.response is not None:
#             print("❌ Graph error body:", e.response.text)
#         raise HTTPException(status_code=500, detail="Graph subscription failed")


# @app.get("/get-token")
# async def get_token(user_email: str):

#     user_email = user_email.strip()
#     token_data = user_tokens.get(user_email)
#     if not token_data:
#         raise HTTPException(status_code=404, detail="User not authorized")
    

#     if not token_data:
#         raise HTTPException(status_code=404, detail="User not authorized")

#     now = datetime.now(timezone.utc)
#     if token_data["expires_at"] <= now:
#         print("🔁 Access token expired, refreshing...")

#         data = {
#             "client_id": os.getenv("CLIENT_ID"),
#             "grant_type": "refresh_token",
#             "refresh_token": token_data["refresh_token"],
#             "scope": "User.Read Mail.Read offline_access",
#             "redirect_uri": os.getenv("REDIRECT_URI"),
#             "client_secret": os.getenv("CLIENT_SECRET"),
#         }

#         async with httpx.AsyncClient() as client:
#             try:
#                 res = await client.post(
#                     "https://login.microsoftonline.com/08423cbb-15b2-4cc9-a5a6-b7b2701a472b/oauth2/v2.0/token",
#                     data=data
#                 )
#                 res.raise_for_status()
#                 refreshed = res.json()

#                 # Update stored token
#                 token_data["access_token"] = refreshed["access_token"]
#                 token_data["refresh_token"] = refreshed.get("refresh_token", token_data["refresh_token"])
#                 token_data["expires_at"] = now + timedelta(seconds=refreshed["expires_in"])

#                 print("✅ Token refreshed")

#             except Exception as e:
#                 print("❌ Failed to refresh token:", str(e))
#                 raise HTTPException(status_code=500, detail="Failed to refresh access token")

#     return { "access_token": token_data["access_token"] }


# @app.get("/get-email-and-token")
# async def get_email_and_token(userId: str):
#     user_email = user_id_to_email.get(userId)
#     if not user_email:
#         raise HTTPException(status_code=404, detail="Email not found for userId")

#     token_data = user_tokens.get(user_email)
#     if not token_data:
#         raise HTTPException(status_code=404, detail="Token not found for this user")

#     now = datetime.now(timezone.utc)
#     if token_data["expires_at"] <= now:
#         print(f"🔁 Token expired for {user_email}, refreshing...")

#         data = {
#             "client_id": os.getenv("CLIENT_ID"),
#             "grant_type": "refresh_token",
#             "refresh_token": token_data["refresh_token"],
#             "scope": "User.Read Mail.Read offline_access",
#             "redirect_uri": os.getenv("REDIRECT_URI"),
#             "client_secret": os.getenv("CLIENT_SECRET"),
#         }

#         async with httpx.AsyncClient() as client:
#             try:
#                 res = await client.post(
#                     "https://login.microsoftonline.com/08423cbb-15b2-4cc9-a5a6-b7b2701a472b/oauth2/v2.0/token",
#                     data=data
#                 )
#                 res.raise_for_status()
#                 refreshed = res.json()

#                 token_data["access_token"] = refreshed["access_token"]
#                 token_data["refresh_token"] = refreshed.get("refresh_token", token_data["refresh_token"])
#                 token_data["expires_at"] = now + timedelta(seconds=refreshed["expires_in"])

#                 print(f"✅ Token refreshed for {user_email}")
#             except Exception as e:
#                 print(f"❌ Refresh failed for {user_email}: {str(e)}")
#                 raise HTTPException(status_code=500, detail="Failed to refresh token")

#     return {
#         "user_email": user_email,
#         "access_token": token_data["access_token"]
#     }


# @app.post("/auth/exchange")
# async def exchange_code(payload: dict):
#     code = payload.get("code")
#     code_verifier = payload.get("code_verifier")

#     if not code or not code_verifier:
#         raise HTTPException(status_code=400, detail="Missing authorization code or code verifier")

#     data = {
#         "client_id": os.getenv("CLIENT_ID"),
#         "scope": "User.Read Mail.Read offline_access",
#         "code": code,
#         "redirect_uri": os.getenv("REDIRECT_URI"),
#         "grant_type": "authorization_code",
        
#         "code_verifier": code_verifier,
#         "client_secret": os.getenv("CLIENT_SECRET"),
#     }

#     try:
#         async with httpx.AsyncClient() as client:
#             res = await client.post(
#                 "https://login.microsoftonline.com/08423cbb-15b2-4cc9-a5a6-b7b2701a472b/oauth2/v2.0/token",
#                 data=data
#             )
#             res.raise_for_status()
#             token_data = res.json()

#             access_token = token_data["access_token"]
#             refresh_token = token_data["refresh_token"]
#             expires_in = token_data["expires_in"]

#             profile_res = await client.get(
#                 f"{GRAPH_BASE}/me",
#                 headers={"Authorization": f"Bearer {access_token}"}
#             )
#             profile_res.raise_for_status()
#             user_data = profile_res.json()

#     except httpx.HTTPStatusError as e:
#         print("❌ Token exchange failed:", e.response.text)
#         raise HTTPException(status_code=e.response.status_code, detail="Token exchange failed")

#     except Exception as e:
#         print("❌ General error during token exchange:", str(e))
#         raise HTTPException(status_code=500, detail="Unexpected error")

#     user_email = user_data.get("mail") or user_data.get("userPrincipalName")
#     user_id = user_data.get("id")
#     if not user_email:
#         raise HTTPException(status_code=400, detail="Could not extract user email")
#     if user_id:
#         user_id_to_email[user_id] = user_email

#     user_tokens[user_email] = {
#         "access_token": access_token,
#         "refresh_token": refresh_token,
#         "expires_at": datetime.now(timezone.utc) + timedelta(seconds=expires_in),
#     }

#     return {
#     "message": f"{user_email} authorized",
#     "access_token": access_token,
#     "refresh_token": refresh_token,
#     "expires_in": expires_in
# }

# @app.get("/debug/user-tokens")
# def debug_user_tokens():
#     return user_tokens
