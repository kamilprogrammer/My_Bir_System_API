from fastapi import FastAPI, HTTPException, Depends, status, Request
from pydantic import BaseModel
from typing import Annotated
import models
from database import engine, session
from sqlalchemy.orm import Session
import uvicorn
from starlette.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta



app = FastAPI()

SECRET_KEY = "#1bir.admin.app#"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_DAYS = 30



pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")





models.Base.metadata.create_all(bind=engine)



class ReportBase(BaseModel):
    userid:int
    name:str
    place:str
    kind:str
    date:str
    report_title:str
    desc:str
    notes:str
    done_by: int
    done_by2: int
    done:bool

class UserBase(BaseModel):
    username:str
    floor:int
    section:str
    password:str
    worker: bool
    admin:bool


class LoginBase(BaseModel):
    username:str
    password:str

class ProcessBase(BaseModel):
    title:str
    desc:str
    date: str
    status: bool
    report_id: int

class SectionBase(BaseModel):
    name:str
    floor:int
    


def get_db():
    db = session()
    try:
        yield db
    finally:
        db.close()    




db_dependency = Annotated[Session, Depends(get_db)]

@app.post("/add", status_code=status.HTTP_201_CREATED)
async def main(report:ReportBase, db:db_dependency, request:Request):
    if request.headers.get("Authorization"):
        
        token = verify_token(token=request.headers.get("Authorization"))
        if token:
            
            db_report = models.Report(**report.__dict__)
            db.add(db_report)
            db.commit()
        else:
            return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")
    else:
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")

@app.get("/users", status_code=status.HTTP_200_OK)
async def users(db:db_dependency, request: Request):
    if request.headers.get("Authorization"):
        token = verify_token(token=request.headers.get("Authorization"))
        user = db.query(models.User).filter(models.User.username == token['sub']).first()  

        if user and user.admin == True:
            users_edit = db.query(models.User).all()
            if users_edit is None:
                raise HTTPException(status_code=404 , detail='There is No Users!')
            return users_edit

        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")
    return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")
@app.get("/employees", status_code=status.HTTP_200_OK)
async def workers(db:db_dependency, request:Request):
    if request.headers.get("Authorization"):
        token = verify_token(token=request.headers.get("Authorization"))
        user = db.query(models.User).filter(models.User.username == token['sub']).first()  

        if user and user.admin == True:
            users_edit = db.query(models.User).filter(models.User.worker == True).all()
            if users_edit is None:
                raise HTTPException(status_code=404 , detail='There is No Employees!')
            return users_edit

        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")
    return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")


@app.put("/admin/{id}", status_code=status.HTTP_200_OK)
async def done(id:int, db:db_dependency, request:Request):
    if request.headers.get("Authorization"):

        token = verify_token(token=request.headers.get("Authorization"))
        user = db.query(models.User).filter(models.User.username == token['sub']).first()  

        if user and user.admin == True:

            user = db.query(models.User).filter(models.User.id == id).first()
            if user is None:
                raise HTTPException(status_code=404, detail="Error: No User!")
            user.admin = True
            db.add(user)
            db.commit()
            db.refresh(user)
            return user

        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")
    return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")

@app.put("/not_admin/{id}", status_code=status.HTTP_200_OK)
async def done(id:int, db:db_dependency, request: Request):
    if request.headers.get("Authorization"):
        token = verify_token(token=request.headers.get("Authorization"))
        user = db.query(models.User).filter(models.User.username == token['sub']).first()  

        if user and user.admin == True:
            user_edit = db.query(models.User).filter(models.User.id == id).first()
            if user_edit is None:
                raise HTTPException(status_code=404, detail="Error: No User!")
            user_edit.admin = False
            db.add(user_edit)
            db.commit()
            db.refresh(user_edit)
            return user_edit
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")
    return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")


@app.put("/worker/{id}", status_code=status.HTTP_200_OK)
async def worker(id:int, db:db_dependency, request: Request):
    if request.headers.get("Authorization"):
        token = verify_token(token=request.headers.get("Authorization"))
        user = db.query(models.User).filter(models.User.username == token['sub']).first()  

        if user and user.admin == True:
            user_edit = db.query(models.User).filter(models.User.id == id).first()
            if user_edit is None:
                raise HTTPException(status_code=404, detail="Error: No User!")
            user_edit.worker =True
            db.add(user_edit)
            db.commit()
            db.refresh(user_edit)
            return user_edit
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")
    return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")

@app.put("/not_worker/{id}", status_code=status.HTTP_200_OK)
async def worker(id:int, db:db_dependency, request: Request):

    if request.headers.get("Authorization"):
        token = verify_token(token=request.headers.get("Authorization"))
        user = db.query(models.User).filter(models.User.username == token['sub']).first()  

        if user and user.admin == True:
            user_edit = db.query(models.User).filter(models.User.id == id).first()
            if user is None:
                raise HTTPException(status_code=404, detail="Error: No User!")
            user_edit.worker = False
            db.add(user_edit)
            db.commit()
            db.refresh(user_edit)
            return user_edit

        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")
    return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")

@app.put("/share/{report_id}/{shared_user1}/{shared_user2}", status_code=status.HTTP_200_OK)
async def share(report_id:int,shared_user1:int,shared_user2:int, db:db_dependency, request: Request):
    if request.headers.get("Authorization"):

        token = verify_token(token=request.headers.get("Authorization"))
        user = db.query(models.User).filter(models.User.username == token['sub']).first()  

        if user and user.admin == True or user and user.worker == True:
            if user.admin == True or user.worker == True:
                report = db.query(models.Report).filter(models.Report.id == report_id).first()
                if report is None:
                    raise HTTPException(status_code=404, detail="Error: No Report!")
                if(shared_user1 == 0) :
                    shared_user1 = shared_user2
                    report.done_by = shared_user1
                    report.done_by2 = 0

                elif(shared_user2 == 0):
                    report.done_by = shared_user1
                    report.done_by2 = 0

                else :
                     report.done_by = shared_user1  
                     report.done_by2 = shared_user2 


                db.add(report)
                db.commit()
                db.refresh(report)
                return report
            return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")      
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")
    return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")
    
    




@app.delete('/del_user/{id}' , status_code=status.HTTP_200_OK)
def del_report(id: int , db : db_dependency, request: Request):
    if request.headers.get("Authorization"):

        token = verify_token(token=request.headers.get("Authorization"))
        user = db.query(models.User).filter(models.User.username == token['sub']).first()  

        if user and user.admin == True:
            user=db.query(models.User).filter(models.User.id == id).first()
            if user is None:
                raise HTTPException(status_code=404 , detail='User is not Found')
            db.delete(user)
            db.commit()
            return "Done"
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")
    return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")
    


def authenticate_user(username: str, password: str, db: Session, user: UserBase):
    db_user = db.query(models.User).filter(user.username == username).first()
    if not db_user:
        return False
    if not pwd_context.verify(password, db_user.password):
        return False
    return {db_user}

def create_access_token(data: dict,admin: bool, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(days=30)
    to_encode.update({"exp": expire, "admin" : admin})
   
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def login_access_token(user:LoginBase, admin:bool, db: Session = Depends(get_db)):
    access_token_expires = timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)

    access_token = create_access_token(
        data={"sub": user.username},admin=admin, expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}


def verify_token(token: str):
    try: 
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=403, detail="Token is invalid or expired")
        return payload
    except JWTError:
        raise HTTPException(status_code=403, detail="Token is invalid or expired")


@app.post("/login", status_code=status.HTTP_201_CREATED)
async def Login(user:LoginBase, db:db_dependency):
    if_user = authenticate_user(user.username, user.password ,db, user=user)
    db_user = db.query(models.User).filter(models.User.username == user.username).first()

    
    if not if_user and db_user:
        token = login_access_token(user=user, db=db_dependency, admin=db_user.admin)
        
        return [db_user, token]
    
    return JSONResponse(status_code=status.HTTP_203_NON_AUTHORITATIVE_INFORMATION, content="203")
    

    


@app.post("/register", status_code=status.HTTP_201_CREATED)
async def register(user:UserBase, db:db_dependency):

    db_user = db.query(models.User).filter(models.User.username == user.username).first()

    if db_user :
        return JSONResponse(status_code=status.HTTP_203_NON_AUTHORITATIVE_INFORMATION, content="203")
        
    
    else :
        hashed_password = pwd_context.hash(user.password)
        user_new = models.User(username= user.username, floor=user.floor, section = user.section, password = hashed_password, worker = user.worker, admin = user.admin)
        
        db.add(user_new)
        db.commit()
        db.refresh(user_new)
        token=login_access_token(admin=user.admin , user=user, db=db)
        return [user_new, token]
    


@app.get("/reports", status_code=status.HTTP_200_OK)
async def reports(db:db_dependency, request: Request):

    if request.headers.get("Authorization"):

        token = verify_token(token=request.headers.get("Authorization"))
    
        if token["admin"] == True:
            reports = db.query(models.Report).all()
            if reports is None:
                raise HTTPException(status_code=404 , detail='There is No reports')
            return reports
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")
    return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")


@app.get("/reports/done", status_code=status.HTTP_200_OK)
async def reports(db:db_dependency, request: Request):

    if request.headers.get("Authorization"):

        token = verify_token(token=request.headers.get("Authorization"))
    
        if token["admin"] == True:
            reports = db.query(models.Report).filter(models.Report.done == True).all()
            if reports is None:
                raise HTTPException(status_code=404 , detail='There is No reports')
            return reports
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")
    return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")


@app.put("/update_user/{id}", status_code=status.HTTP_200_OK)
async def update_user(id:int,user_new:UserBase, db:db_dependency, request: Request):

    if request.headers.get("Authorization"):
        token = verify_token(token=request.headers.get("Authorization"))

        if token["admin"] == True:
            user = db.query(models.User).filter(models.User.id == id).first()


            if user is None:
                raise HTTPException(status_code=404, detail="Error: No User!")
            user.username = user_new.username
            user.floor = user_new.floor
            user.section = user_new.section
            user.password = pwd_context.hash(user_new.password)
            user.worker = user_new.worker
            user.admin = user_new.admin

            db.add(user)
            db.commit()
            db.refresh(user)
            return user

        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")
    return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")

@app.get("/user/{id}", status_code=status.HTTP_200_OK)
async def user(id:int, db:db_dependency, request: Request):

    if request.headers.get("Authorization"):
        token = verify_token(token=request.headers.get("Authorization"))

        user_me = db.query(models.User).filter(models.User.username == token['sub']).first()  

        if user_me:
                if user_me.admin == True:

                    user = db.query(models.User).filter(models.User.id == id).first()

                    token = login_access_token(user=user, db=db_dependency, admin=user_me.admin)

                    return [user, token] if user else HTTPException(status_code=404, detail="User not found!")
                
                if user_me.admin == False:
                    token = login_access_token(user=user_me, db=db_dependency, admin=user_me.admin)
                    
                    return [user_me, token]

        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")
    return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")


@app.get("/sections/{floor}", status_code=status.HTTP_200_OK)
async def user(floor:int, db:db_dependency):
    section = db.query(models.Section).filter(models.Section.floor == floor).all()
    if section is None:
        raise HTTPException(status_code=404, detail="There is no Sections here!")
    return section


@app.get("/reports/{user_id}", status_code=status.HTTP_200_OK)
async def reports_user(user_id:int, db:db_dependency, request : Request):
    if request.headers.get("Authorization"):
        
        token = verify_token(token=request.headers.get("Authorization"))
        
        user = db.query(models.User).filter(models.User.username == token['sub']).first()  

        if token and user:
            
            if str(user.id) == str(user_id) or user.admin == True:
               
                reports_1 = db.query(models.Report).filter(models.Report.userid == user_id).all()
                reports_2 = db.query(models.Report).filter(models.Report.done_by == user_id).all()
                reports_3 = db.query(models.Report).filter(models.Report.done_by2 == user_id).all()
                
                if reports_1 == [] and reports_2 == [] and reports_3 == []:
                    raise HTTPException(status_code=404, detail="There is no Reports")
                elif reports_1 != [] and reports_2 != [] and reports_3 != []:
                    
                    for report1 in reports_1:
                        
                        for report2 in reports_2:
                            
                            for report3 in reports_3:
                                
                                if report1 == report2:
                                    reports_2.remove(report2)
                                    
                                if report1 == report3:
                                    
                                    reports_3.remove(report3)
                                    
                                if report2 == report3:
                                    
                                    reports_3.remove(report3)
                                    
                    return reports_1 + reports_2 + reports_3
                

                elif reports_1 != [] and reports_2 == [] and reports_3 == []:
                    return reports_1
                
                
                elif reports_1 != [] and reports_2 != [] and reports_3 == []:
                    for report1 in reports_1:
                        for report2 in reports_2:
                            if report1 == report2:
                                reports_2.remove(report2)
                    return reports_1 + reports_2

                elif reports_1 != [] and reports_3 != [] and reports_2 == []:
                    for report1 in reports_1:
                        for report3 in reports_3:
                            if report1 == report3:
                                reports_3.remove(report3)
                    return reports_1 + reports_3
            else:
                return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")
        else:
            raise HTTPException(status_code=404, detail="There is no User with this ID :)")
    else:
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")

@app.get("/report/{report_id}", status_code=status.HTTP_200_OK)
async def report(report_id:int, db:db_dependency, request : Request):
    if request.headers.get("Authorization"):
        token = verify_token(token=request.headers.get("Authorization"))
        user = db.query(models.User).filter(models.User.username == token['sub']).first()
        if user and user.admin == True: 
            report = db.query(models.Report).filter(models.Report.id == report_id).first()
            if report is None:
                raise HTTPException(status_code=404, detail="There is no Reports")
            return report

        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")
    return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")


@app.put("/done/{id}", status_code=status.HTTP_200_OK)
async def done(id:int, db:db_dependency, request: Request):
    if request.headers.get("Authorization"):
        token = verify_token(token=request.headers.get("Authorization"))
        
        user = db.query(models.User).filter(models.User.username == token['sub']).first()
        if user and user.admin == True or user and user.worker == True: 
            report = db.query(models.Report).filter(models.Report.id == id).first()
            if report is None:
                raise HTTPException(status_code=404, detail="Error: No Report!")
            report.done = True
            db.add(report)
            db.commit()
            db.refresh(report)
            return report
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")
    return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")


@app.put("/notyet/{id}", status_code=status.HTTP_200_OK)
async def done(id:int, db:db_dependency, request:Request):
    
    if request.headers.get("Authorization"):
        
        token = verify_token(token=request.headers.get("Authorization"))
        user = db.query(models.User).filter(models.User.username == token['sub']).first()
        if user and user.admin == True or user and user.worker == True: 
            report = db.query(models.Report).filter(models.Report.id == id).first()
            
            if report is None:
                raise HTTPException(status_code=404, detail="Error: No Report!")
            report.done = False
            db.add(report)
            db.commit()
            db.refresh(report)
            return report
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")
    return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")


@app.delete("/delete/{id}", status_code=status.HTTP_200_OK)
async def done(id:int, db:db_dependency, request: Request):
    if request.headers.get("Authorization"):
        token = verify_token(token=request.headers.get("Authorization"))
        user = db.query(models.User).filter(models.User.username == token['sub']).first()

        if user and user.admin == True: 
            report = db.query(models.Report).filter(models.Report.id == id).first()
            if report is None:
                raise HTTPException(status_code=404, detail="Error: No Report!")

            db.delete(report)
            db.commit()

        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")
    return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")

@app.get("/about", status_code=status.HTTP_200_OK)
def get_about(request:Request):
    if request.headers.get("Authorization"):
        token = verify_token(token=request.headers.get("Authorization"))
        if token:
            result = {"data" : "هذا النص قابل للتغيير و هو يتحدث عن محتوى التطبيق و الفائدة منه"}
            return result
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")
    return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")

@app.get("/processes")
def get_processes(db:db_dependency, request:Request, status_code=status.HTTP_200_OK):
    if request.headers.get("Authorization"):
        token = verify_token(token=request.headers.get("Authorization"))
    
        if token and token["admin"] == True or token and token["worker"] == True:
            processes = db.query(models.Process).all()
            if processes is None:
                raise HTTPException(status_code=404 , detail='There is No Processes')
            return processes
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")
    return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")


@app.post("/add_proccess", status_code=status.HTTP_201_CREATED)
def add_process(proccess: ProcessBase , db:db_dependency, request:Request):
    if request.headers.get("Authorization"):
        
        token = verify_token(token=request.headers.get("Authorization"))
        if token:
            
            db_proccess = models.Process(**proccess.__dict__)
            db.add(db_proccess)
            db.commit()
        else:
            return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")
    else:
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")

@app.put("/update_proccess/{process_id}", status_code=status.HTTP_201_CREATED)
def update_process(db:db_dependency, request:Request, process:ProcessBase, process_id:int):
    if request.headers.get('Authorization'):
        token = verify_token(token=request.headers.get("Authorization"))
        if token:
            db_process = db.query(models.Process).filter(process_id == models.Process.id).first()
            if db_process is None:
                return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content="404")
            db_process.title = process.title
            db_process.date = process.date
            db_process.desc = process.desc
            db_process.status = process.status
            db_process.report_id = process.report_id
            db.add(db_process)
            db.commit()
            db.refresh(db_process)
            return db_process
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")
    return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")

@app.delete("/proccess/{process_id}", status_code=status.HTTP_200_OK)
def del_process(db:db_dependency, request:Request, process_id:int):
    if request.headers.get('Authorization'):
        token = verify_token(token=request.headers.get("Authorization"))
        if token:
            db_process = db.query(models.Process).filter(process_id == models.Process.id).first()
            if db_process is None:
                return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content="404")
            db.delete(db_process)
            db.commit()
            return JSONResponse(status_code=status.HTTP_200_OK, content="200")
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")
    return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")



@app.get("/analytics/users/month", status_code=status.HTTP_200_OK)
def analytics_users(db:db_dependency, request:Request):
    if request.headers.get("Authorization"):
        token = verify_token(token=request.headers.get("Authorization"))
        if token and token['admin'] == True:
            users = db.query(models.User).all()
            reports = db.query(models.Report).all()
            reports_Done = db.query(models.Report).filter(models.Report.done == True).all()
            reports_all = []
            for report in reports:
                if str(datetime.strptime(report.date, "%Y-%m-%d").date().month) == str(datetime.now().date().month):
                    reports_all.append(report)
                

            result = []
            
            for user in users:
                inc = 0
                for report in reports_all:
                    
                    if int(user.id) == int(report.done_by) or int(user.id) == int(report.done_by2):
                        if [user, inc] in result:
                            i = result.index([user, inc])
                            result.pop(i)
                            inc += 1
                            result.append([user, inc])
                        else:
                            inc += 1
                            result.append([user, inc])
            
            return [result, len(reports), len(reports_Done)]

                
            
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")
    return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")


                
@app.get("/analytics/users/day", status_code=status.HTTP_200_OK)
def analytics_users(db:db_dependency, request:Request):
    if request.headers.get("Authorization"):
        token = verify_token(token=request.headers.get("Authorization"))
        if token and token['admin'] == True:
            users = db.query(models.User).all()
            reports = db.query(models.Report).all()
            reports_all = []

    
            result = [] 

            for report in reports:    
                if str(datetime.strptime(report.date, "%Y-%m-%d").date().day) == str(datetime.now().date().day) and str(datetime.strptime(report.date, "%Y-%m-%d").date().month) == str(datetime.now().date().month):
                    reports_all.append(report)
                else:
                    reports.remove(report)

            print(len(reports_all))
            
            for user in users:
                inc = 0

                
                #print(len(reports))

                for report in reports_all:

                    if int(user.id) == int(report.done_by) or int(user.id) == int(report.done_by2):
                        #print(report.id)

                        if [user, inc] in result:
                            i = result.index([user, inc])
                            result.pop(i)
                            inc += 1
                            result.append([user, inc])
                        else:
                            inc += 1
                            result.append([user, inc])
            reports_Done = db.query(models.Report).filter(models.Report.done == True).all()
            return [result, len(reports),len(reports_Done)]

                
            
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")
    return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")




@app.get("/analytics/reports/month", status_code=status.HTTP_200_OK)
def analytics_reports(db:db_dependency, request:Request):
    
    if request.headers.get("Authorization"):
        token = verify_token(token=request.headers.get("Authorization"))
        
        if token and token['admin'] == True:


            date = datetime.now().month
            reports_all = db.query(models.Report).all()
            reports_all_date = []

            for report in reports_all:
                if datetime.strptime(str(report.date), "%Y-%m-%d").date().month == date:
                    reports_all_date.append(report)



            reports_done = db.query(models.Report).filter(models.Report.done == True).all()
            reports_done_date = 0

            for report in reports_done:
                if  datetime.strptime(str(report.date), "%Y-%m-%d").date().month == date:
                    reports_done_date += 1
            
            #reports graph analytics every month reports
            this_month = datetime.now().date().month
            prev_month = this_month - 1
            prev_2_month = this_month - 2
            
            reports_analytics_date_this_month = 0
            reports_analytics_date_prev_month = 0
            reports_analytics_date_prev_2_month = 0
            for report in reports_all:
                if datetime.strptime(str(report.date), "%Y-%m-%d").date().month == this_month:
                    reports_analytics_date_this_month += 1
                elif datetime.strptime(str(report.date), "%Y-%m-%d").date().month == prev_month:
                    reports_analytics_date_prev_month += 1
                elif datetime.strptime(str(report.date), "%Y-%m-%d").date().month == prev_2_month:
                    reports_analytics_date_prev_2_month += 1
            

            #report slide("horizintal :)" graph) that shows every floor's reports Number(Length)
            First_Floor = {"reports" : 0, "section" :""}
            Second_Floor = 0
            Third_Floor = 0
            Fourth_Floor = 0
            Fifth_Floor = 0
            Sixth_Floor = 0
            Seventh_Floor = 0
            Eigthth_Floor = 0
            Nineth_Floor = 0
            Tenth_Floor = 0

            for report in reports_all:
                userid = report.userid
                user = db.query(models.User).filter(models.User.id == int(userid)).first()
                if user:

                
                    if user.floor == 1:
                        First_Floor.update("reports", First_Floor['reports'] + 1)
                        First_Floor.update("section", user.section)
                    if user.floor == 2:
                        Second_Floor += 1  
                    if user.floor == 3:
                        Third_Floor += 1  
                    if user.floor == 4:
                        Fourth_Floor += 1  
                    if user.floor == 5:
                        Fifth_Floor += 1  
                    if user.floor == 6:
                        Sixth_Floor += 1  
                    if user.floor == 7:
                        Seventh_Floor += 1  
                    if user.floor == 8:
                        Eigthth_Floor += 1  
                    if user.floor == 9:
                        Nineth_Floor += 1  
                    if user.floor == 10:
                        Tenth_Floor += 1  
                    
                    l1 = {"1":int(First_Floor['reports']), "2":Second_Floor, "3":Third_Floor, "4":Fourth_Floor, "5":Fifth_Floor, "6":Sixth_Floor, "7":Seventh_Floor, "8":Eigthth_Floor, "9":Nineth_Floor, "10":Tenth_Floor}
                    
                    biggest1 = max(l1.values())
                    biggest1_floor = 0
                    
                    for i in range(10):
                        if l1[str(i+1)] == biggest1:
                            l1[str(i+1)] = 0
                            biggest1_floor = i+1


                    biggest2 = max(l1.values())
                    biggest2_floor = 0

                    for i in range(10):
                        if l1[str(i+1)] == biggest2:
                            l1[str(i+1)] = 0
                            biggest2_floor = i+1


                    biggest3= max(l1.values())
                    biggest3_floor = 0

                    for i in range(10):
                        if l1[str(i+1)] == biggest3:
                            
                            l1[str(i+1)] = 0   
                            biggest3_floor = i+1 
                    
                    
                    

            
                

            return [{"total":len(reports_all),
             "done" : reports_done_date}, 
            {"reports_m":reports_analytics_date_this_month,
             "report__m" : reports_analytics_date_prev_month,
              "report___m" : reports_analytics_date_prev_2_month}, 
              {biggest1_floor:biggest1, biggest2_floor:biggest2, biggest3_floor:biggest3}]

            
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")
    return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")



@app.get("/analytics/reports/week", status_code=status.HTTP_200_OK)
def analytics_reports(db:db_dependency, request:Request):
    if request.headers.get("Authorization"):
        token = verify_token(token=request.headers.get("Authorization"))
        
        if token and token['admin'] == True:


            date = datetime.now().day
            month = datetime.now().month
            if date <= 7:
                date = 1
            elif date > 7 and date <= 14:
                date = 2
            elif date > 14 and date <= 21:
                date = 3
            elif date > 21 and date <= 30:
                date = 4
            reports_all = db.query(models.Report).all()
            reports_all_date = []

            for report in reports_all:
                report_date = datetime.strptime(str(report.date), "%Y-%m-%d").date().day
                report_date_month = datetime.strptime(str(report.date), "%Y-%m-%d").date().month
                if report_date  <= 7 and date == 1 and report_date_month == month:
                    reports_all_date.append(report)
                elif report_date  > 7 and report_date <= 14 and date == 2 and report_date_month == month:
                    reports_all_date.append(report)
                elif report_date > 14 and report_date <= 21 and date == 3 and report_date_month == month:
                    reports_all_date.append(report)
                elif report_date > 21 and report_date <= 30 and date == 4 and report_date_month == month:
                    reports_all_date.append(report)



            reports_done = db.query(models.Report).filter(models.Report.done == True).all()
            reports_done_date = []

            for report in reports_done:
                report_date = datetime.strptime(str(report.date), "%Y-%m-%d").date().day
                report_date_month = datetime.strptime(str(report.date), "%Y-%m-%d").date().month
                if report_date  <= 7 and date == 1 and report_date_month == month:
                    reports_done_date.append(report)
                elif report_date  > 7 and report_date <= 14 and date == 2 and report_date_month == month:
                    reports_done_date.append(report)
                elif report_date > 14 and report_date <= 21 and date == 3 and report_date_month == month:
                    reports_done_date.append(report)
                elif report_date > 21 and report_date <= 30 and date == 4 and report_date_month == month:
                    reports_done_date.append(report)
                

            
            return [{"total":len(reports_all_date), "done" : len(reports_done_date)}]

            
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")
    return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")



@app.get("/analytics/reports/day", status_code=status.HTTP_200_OK)
def analytics_reports(db:db_dependency, request:Request):
    if request.headers.get("Authorization"):
        token = verify_token(token=request.headers.get("Authorization"))
        
        if token and token['admin'] == True:


            date = datetime.now().day
            reports_all = db.query(models.Report).all()
            reports_all_date = []

            for report in reports_all:
                if datetime.strptime(str(report.date), "%Y-%m-%d").date().day == date:
                    reports_all_date.append(report)



            reports_done = db.query(models.Report).filter(models.Report.done == True).all()
            reports_done_date = []

            for report in reports_done:
                if  datetime.strptime(str(report.date), "%Y-%m-%d").date().day == date:
                    reports_done_date.append(report)
            

            
            return [{"total":len(reports_all_date), "done" : len(reports_done_date)}]

            
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")
    return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")






@app.get("/analytics/reports", status_code=status.HTTP_200_OK)
def analytics_reports(db:db_dependency, request:Request):
    if request.headers.get("Authorization"):
        token = verify_token(token=request.headers.get("Authorization"))
        
        if token and token['admin'] == True:
            reports_all = db.query(models.Report).all()
            reports_done = db.query(models.Report).filter(models.Report.done == True).all()
            return [{"total":len(reports_all), "done" : len(reports_done)}]

            pass
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")
    return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content="401")

    


app.add_middleware(
CORSMiddleware,
allow_origins=["*"],
allow_credentials=True,
allow_methods=["*"],
allow_headers=["*"],
)

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=3666,
        log_level="debug",
        reload=True,
    )