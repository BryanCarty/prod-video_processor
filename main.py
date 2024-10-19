from pydantic import BaseModel
from fastapi import FastAPI, HTTPException, Response, Header, Request
from fastapi.middleware.cors import CORSMiddleware
import base64
import os
import subprocess
import uvicorn
import json
import uuid
import math
import shutil
from sketchify import sketch
import jwt
from dotenv import load_dotenv
from PIL import Image, ImageDraw, ImageFont
from reportlab.lib.pagesizes import A4, landscape
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
import datetime
import zipfile
from io import BytesIO
from fastapi.responses import StreamingResponse
from typing import Dict
from datetime import datetime
import pyclamd
import logging
import time
import uvicorn
import argparse


# Function to parse command-line arguments
def parse_args():
    parser = argparse.ArgumentParser(description="Run the FastAPI app with a specific environment")
    parser.add_argument('env', type=str, help="Environment to run (dev or prod)")
    args = parser.parse_args()
    return args

# Parse the environment flag from the command-line
args = parse_args()
env = args.env[4:]

print(f'Loading env: {env}')


load_dotenv(env)

VIDEO_DIR = os.getenv('VIDEO_DIR')
FONT = os.getenv('FONT')
LOGO = os.getenv('LOGO')
THICKNESS_PER_PAGE =  float(os.getenv('THICKNESS_PER_PAGE'))
ALLOW_ORIGINS =  os.getenv('ALLOW_ORIGINS')
HOST =  os.getenv('HOST')
PORT =  int(os.getenv('PORT'))
LOG_FILE =  os.getenv('LOG_FILE')


logFormatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s] [%(filename)s:%(lineno)d] %(message)s")
rootLogger = logging.getLogger()
rootLogger.setLevel(logging.DEBUG)

fileHandler = logging.FileHandler(LOG_FILE)
fileHandler.setFormatter(logFormatter)
rootLogger.addHandler(fileHandler)

consoleHandler = logging.StreamHandler()
consoleHandler.setFormatter(logFormatter)
rootLogger.addHandler(consoleHandler)

rootLogger.info('Initializing Video Processor...')

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[ALLOW_ORIGINS],  # Allows access from all origins, you can specify specific origins if needed
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],  # Allows these HTTP methods
    allow_headers=["*"],  # Allows all headers
)


# Initialize the ClamD client
cd = pyclamd.ClamdUnixSocket()  # or ClamdNetworkSocket for TCP

# Check if the ClamD server is reachable
if cd.ping():
    rootLogger.info('ClamD is running...')
else:
    rootLogger.error('Failed to start ClamD!')
    rootLogger.info('Shutting down...')
    raise SystemExit()


def is_malicious(file_path):
    with open(file_path, 'rb') as file_stream:  # open the file as a binary stream
        result = cd.scan_stream(file_stream)
    rootLogger.debug(f'Is Malicious Result: {result}')
    if result:
        return True
    return False
    

class CropVideoDetails(BaseModel):
    encoded_video: str
    x_start_percent: float
    y_start_percent: float
    x_width_percent: float
    y_height_percent: float



@app.get("/ping")
async def ping():
    return {"message": "pong"}


@app.post("/crop_video")
async def crop_video(video_details: CropVideoDetails, request: Request, response: Response):
    video_id=""
    try:
        start_time = time.time()
        rootLogger.info(f'crop_video:Received request to /crop_video with arguments: x_start_percent={video_details.x_start_percent}, y_start_percent={video_details.y_start_percent}, x_width_percent={video_details.x_width_percent}, y_height_percent={video_details.y_height_percent}')
        # Validate base64 encoding and decode
        base64_video = video_details.encoded_video.split(";base64,")
        if len(base64_video) != 2:
            raise ValueError("Invalid base64 encoding")
        decoded_data = base64.b64decode(base64_video[1])
        
        # Generate a unique ID for the video processing request
        video_id = str(uuid.uuid4())
        rootLogger.debug(f'crop_video:Creating video id: {video_id}')
        
        # Create directory using the generated ID
        video_dir = os.path.join(VIDEO_DIR, video_id)
        rootLogger.debug(f'{video_id}:crop_video:Creating video directory: {video_dir}')
        os.makedirs(video_dir, mode=0o775, exist_ok=True)

        # Determine file format
        file_format = base64_video[0].split('/')[1]

        if file_format == "quicktime":
            file_format = "mov"

        if file_format != "mp4" and file_format != "mov":
            raise ValueError(f"{video_id}:crop_video: Unsupported video format, file_format={file_format}")
        

        # Save uploaded video
        video_path = os.path.join(video_dir, f'base_video.{file_format}')
        rootLogger.debug(f'{video_id}:crop_video: Saving base video: {video_path}')
        with open(video_path, "wb") as file:
            file.write(decoded_data)


        if is_malicious(video_path):
            os.remove(video_path)
            raise ValueError(f"{video_id}:crop_video: Malicious Video Upload Attempt: {video_path}")
            

        # Get rotation info
        command = [
            "ffprobe", 
            "-v", "0", 
            "-select_streams", "v:0", 
            "-show_entries", "stream_side_data=rotation",
            "-of", "json", 
            video_path
        ]

        try:
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            video_info = json.loads(result.stdout)
            rotation = int(video_info['streams'][0].get('side_data_list', [{}])[0].get("rotation", 0))
            rootLogger.debug(f'{video_id}:crop_video: Rotation: {rotation}')
        except Exception as e:
            raise OSError(f"Unable to get rotation data: {e} : {result}")

        # Get video dimensions using ffprobe
        command = [
            "ffprobe", 
            "-v", "error", 
            "-select_streams", "v:0", 
            "-show_entries", "stream=width,height",
            "-of", "json", 
            video_path
        ]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        video_info = json.loads(result.stdout)




        # Extract width and height
        width = video_info['streams'][0]['width']
        height = video_info['streams'][0]['height']

        if rotation not in [0, 180 -180]:
            width, height = height, width

        rootLogger.debug(f'{video_id}:crop_video: Video dimensions retrieved: {width}x{height}')



        # Calculate cropping dimensions
        x_start = int(width * video_details.x_start_percent)
        y_start = int(height * video_details.y_start_percent)
        x_width = int(width * video_details.x_width_percent)
        y_height = int(height * video_details.y_height_percent)

        # Output path for cropped video
        cropped_video_path = os.path.join(video_dir, f'cropped_video.mp4')


        
        # FFmpeg command to crop the video
        ffmpeg_command = [
            "ffmpeg",
            "-i", video_path,
            "-filter:v", f"crop={x_width}:{y_height}:{x_start}:{y_start}",
            "-c:v", "libx264",
            "-an",
            cropped_video_path
        ]

        
        # Execute FFmpeg command
        rootLogger.debug(f'{video_id}:crop_video: Saving cropped video to {cropped_video_path}')
        subprocess.run(ffmpeg_command, check=True)

        rootLogger.debug(f'{video_id}:crop_video: Removing base video: {video_path}')
        os.remove(video_path)

        # Read cropped video as bytes
        with open(cropped_video_path, "rb") as cropped_file:
            cropped_video_bytes = cropped_file.read()

        # Encode cropped video bytes to base64
        cropped_video_base64 = base64.b64encode(cropped_video_bytes).decode('utf-8')

        # Return success message, generated video ID, and base64 encoded cropped video
        execution_time = time.time()-start_time
        rootLogger.info(f'{video_id}:crop_video: Exiting /crop_video with status 201, after {execution_time} seconds')
        response.status_code = 201 
        return {
            "id": video_id,
            "video": f"data:video/mp4;base64,{cropped_video_base64}"
        }

    except (base64.binascii.Error, ValueError) as e:
        rootLogger.debug(f'{video_id}:crop_video: Error 400 occurred: {str(e)}', stacklevel=2)
        raise HTTPException(status_code=400, detail="Invalid base64-encoded data")
    except OSError as e:
        rootLogger.debug(f'{video_id}:crop_video: Error 500 occurred: {str(e)}', stacklevel=2)
        raise HTTPException(status_code=500, detail=f"Internal Server error")
    except Exception as e:
        rootLogger.debug(f'{video_id}:crop_video: An unexpected error occurred: {str(e)}', stacklevel=2)
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred")




def convert_to_ffmpeg_time_format(time):
    seconds = math.floor(time)
    milliseconds = round(1000*(time-seconds))
    seconds= str(seconds)if seconds>=10 else f'0{seconds}'
    milliseconds = str(milliseconds) if milliseconds >=100 else (f'0{milliseconds}' if milliseconds >=10 else f'00{milliseconds}')
    return f'00:00:{seconds}.{milliseconds}'



def get_video_info(video_file):
    # Run ffprobe to get video stream info
    ffprobe_cmd = [
        "ffprobe",
        "-v", "error",
        "-select_streams", "v:0",
        "-show_entries", "stream=r_frame_rate,nb_frames",
        "-of", "default=noprint_wrappers=1:nokey=1",
        video_file
    ]
    
    # Run the ffprobe command
    result = subprocess.run(ffprobe_cmd, capture_output=True, text=True, check=True)
    
    # Extract the information
    output = result.stdout.strip().split('\n')
    
    if len(output) < 2:
        raise ValueError("Unexpected ffprobe output format")

    fps_str = output[0]
    total_frames_str = output[1]


    
    # Calculate FPS
    if "/" in fps_str:
        num, denom = map(int, fps_str.split("/"))
        fps = num / denom
    else:
        fps = float(fps_str)
    
    # Parse total frames
    total_frames = int(total_frames_str)
    
    return fps, total_frames
    


class TrimVideoDetails(BaseModel):
    id: str
    start_time: float
    end_time: float


@app.post("/trim_video")
async def trim_video(video_details: TrimVideoDetails, request: Request, response: Response):
    try:
        video_id=""
        start_time = time.time()
        video_id = video_details.id
        rootLogger.info(f'{video_id}:trim_video:Received request to /trim_video with arguments: id={video_details.id}, start_time={video_details.start_time}, end_time={video_details.end_time}')



        # Path to the video files
        video_file = os.path.join(VIDEO_DIR, video_id, f'cropped_video.mp4')
        trimmed_video_path = os.path.join(VIDEO_DIR, video_id, f'trimmed_video.mp4')

        ffmpeg_command = [  
            "ffmpeg",
            "-ss", convert_to_ffmpeg_time_format(video_details.start_time), 
            "-i", video_file,
            "-t", convert_to_ffmpeg_time_format(video_details.end_time - video_details.start_time),
            "-c:v", "libx264",  
            "-an",  
            trimmed_video_path
        ]

        rootLogger.debug(f'{video_id}:trim_video: Saving trimmed video to {trimmed_video_path}')
        subprocess.run(ffmpeg_command, check=True)

        # Remove original video file after trimming
        rootLogger.debug(f'{video_id}:trim_video: Removing cropped video: {video_file}')
        os.remove(video_file)

        # Read trimmed video bytes
        with open(trimmed_video_path, "rb") as trimmed_video:
            trimmed_video_bytes = trimmed_video.read()

        # Encode cropped video bytes to base64
        trimmed_video_base64 = base64.b64encode(trimmed_video_bytes).decode('utf-8')

        # Return response
        execution_time = time.time()-start_time
        rootLogger.info(f'{video_id}:trim_video: Exiting /trim_video with status 201, after {execution_time} seconds')
        response.status_code = 201
        return {
            "id": video_details.id,
            "video": f"data:video/mp4;base64,{trimmed_video_base64}"
        }

    except subprocess.CalledProcessError as e:
        rootLogger.debug(f'{video_id}:trim_video: Error 500 occurred:subprocess.CalledProcessError: {str(e)}', stacklevel=2)
        raise HTTPException(status_code=500, detail="Internal Server Error")
    except OSError as e:
        rootLogger.debug(f'{video_id}:trim_video: Error 500 occurred:OSError: {str(e)}', stacklevel=2)
        raise HTTPException(status_code=500, detail="Internal Server Error")
    except Exception as e:
        rootLogger.debug(f'{video_id}:trim_video: Error 500 Unexpected Error: {str(e)}', stacklevel=2)
        raise HTTPException(status_code=500, detail="Internal Server Error")









def extract_frames(dir, name, file_format, extraction_num):
    frames_dir = f'{dir}/frames'

    os.makedirs(frames_dir, exist_ok=True)
    if extraction_num:
        command = f'ffmpeg -i "{dir}/{name}.{file_format}" -vf "select=not(mod(n\,{extraction_num}))" -vsync vfr "{frames_dir}/frame%03d.png"'
    else:
        command = f'ffmpeg -i "{dir}/{name}.{file_format}" -vsync vfr "{frames_dir}/frame%03d.png"'
    completed_process = subprocess.run(command, shell=True)
    stdout = completed_process.stdout
    stderr = completed_process.stderr
    return stdout, stderr




class VideoConvertDetails(BaseModel):
    id: str
    scale_factor: int # Should default to 10
    sketchify: bool

@app.post("/convert_video")
async def convert_video(video_details: VideoConvertDetails, request: Request, response: Response):
    try:
        video_id=""
        start_time = time.time()
        video_id = video_details.id
        rootLogger.info(f'{video_id}:convert_video:Received request to /convert_video with arguments: id={video_details.id}, scale_factor={video_details.scale_factor}, sketchify={video_details.sketchify}')

        video_dir = os.path.join(VIDEO_DIR, video_id)

        # Reset final frames directory
        final_frames_dir = f'{video_dir}/frames_to_return'
        if os.path.exists(final_frames_dir):
            rootLogger.debug(f'{video_id}:convert_video: Resetting frames_to_return directory: {final_frames_dir}')
            shutil.rmtree(final_frames_dir)
        os.makedirs(final_frames_dir, exist_ok=True)

        # If the frames directory doesn't exist, create it
        if not os.path.exists(f'{video_dir}/frames'): # Should stay constant
            rootLogger.debug(f'{video_id}:convert_video: Extracting frames from {video_dir}/trimmed_video.mp4 into {video_dir}/frames')
            extract_frames(video_dir, "trimmed_video", "mp4", 0)


        if video_details.sketchify:
            rootLogger.debug(f'{video_id}:convert_video: Sketchifying contents of {video_dir}/frames/ into {final_frames_dir}')
            for filename in os.listdir(f'{video_dir}/frames'):
                sketch.normalsketch(f'{video_dir}/frames/{filename}', final_frames_dir, filename.split('.')[0], scale=video_details.scale_factor)
        else:
            # Move the contents of the frames directory to the final frames directory
            rootLogger.debug(f'{video_id}:convert_video: (Not sketchifying) Moving contents of {video_dir}/frames/ into {final_frames_dir}')
            for filename in os.listdir(f'{video_dir}/frames'):
                source_item = os.path.join(f'{video_dir}/frames', filename)
                destination_item = os.path.join(final_frames_dir, filename)
                shutil.copy(source_item, destination_item)


        if os.path.exists(f"{video_dir}/processed_video.mp4"):
            rootLogger.debug(f'{video_id}:convert_video: Removing {video_dir}/processed_video.mp4')
            os.remove(f"{video_dir}/processed_video.mp4")

        command = f'ffmpeg -i "{video_dir}/frames_to_return/frame%03d.png" -c:v libx264 "{video_dir}/processed_video.mp4"'

        rootLogger.debug(f'{video_id}:convert_video: Creating {video_dir}/processed_video.mp4 from the contents of {video_dir}/frames_to_return/')
        subprocess.run(command, shell=True, check=True)

        with open(f"{video_dir}/processed_video.mp4", "rb") as reconstructed_video:
            reconstructed_video_bytes = reconstructed_video.read()

        # Encode cropped video bytes to base64
        reconstructed_video_base64 = base64.b64encode(reconstructed_video_bytes).decode('utf-8')

        execution_time = time.time()-start_time
        rootLogger.info(f'{video_id}:convert_video: Exiting /convert_video with status 201, after {execution_time} seconds')
        response.status_code = 201
        return {
            "id": video_details.id,
            "video": f"data:video/mp4;base64,{reconstructed_video_base64}"
        }
    except Exception as e:
        rootLogger.debug(f'{video_id}:convert_video: Error 500 Unexpected Error: {str(e)}', stacklevel=2)
        raise HTTPException(status_code=500, detail=f"Internal Server Error")



def count_files(directory):
    # List comprehension to get all files in the directory
    files = [file for file in os.listdir(directory) if os.path.isfile(os.path.join(directory, file))]
    # Return the count of files
    return len(files)


def draw_dashed_line(draw, start_pos, end_pos, dash_length=25, space_length=10, color=(0, 0, 0)):
    x1, y1 = start_pos
    x2, y2 = end_pos
    total_length = ((x2 - x1) ** 2 + (y2 - y1) ** 2) ** 0.5
    dashes = int(total_length // (dash_length + space_length))
    for i in range(dashes):
        start_x = x1 + (x2 - x1) * (i * (dash_length + space_length) / total_length)
        start_y = y1 + (y2 - y1) * (i * (dash_length + space_length) / total_length)
        end_x = x1 + (x2 - x1) * ((i * (dash_length + space_length) + dash_length) / total_length)
        end_y = y1 + (y2 - y1) * ((i * (dash_length + space_length) + dash_length) / total_length)
        draw.line([(start_x, start_y), (end_x, end_y)], fill=color, width=12)


class VideoFinalizeDetails(BaseModel):
    id: str
    video: str
    title: str
    message: str


def extract_number_sort(filename):
    try:
        # Extract the numeric part from the filename
        return int(filename.split('frame')[2].split('.')[0])
    except (IndexError, ValueError):
        # Handle cases where filename doesn't match expected format
        return float('-inf')

@app.post("/finalize_video")
async def finalize_video(video_details: VideoFinalizeDetails, request: Request, response: Response):
    try:
        video_id=""
        start_time = time.time()
        video_id = video_details.id
        rootLogger.info(f'{video_id}:finalize_video:Received request to /finalize_video with arguments: id={video_details.id}, title={video_details.title}, message={video_details.message}')


        video_dir = os.path.join(VIDEO_DIR, video_id)
        finalized_video_path = f'{video_dir}/finalized_video'

        # Create directory if it doesn't exist
        rootLogger.debug(f'{video_id}:finalize_video: Creating finalized video path ({finalized_video_path}) if doesn\'t exist')
        os.makedirs(finalized_video_path, exist_ok=True)

        # Validate base64 encoding and decode video data
        base64_video = video_details.video.split(";base64,")
        if len(base64_video) != 2:
            raise ValueError(f"{video_id}:finalize_video: Invalid base64 encoding")
        
        decoded_data = base64.b64decode(base64_video[1])

        # Determine file format
        file_format = base64_video[0].split('/')[1]

        if file_format != "mp4":
            raise ValueError(f"{video_id}:finalize_video: Unsupported video format")

        # Write decoded data to video file
        video_path = os.path.join(finalized_video_path, f'final.mp4')
        rootLogger.debug(f'{video_id}:finalize_video: Writing video to {finalized_video_path}')

        with open(video_path, "wb") as file:
            file.write(decoded_data)

        if is_malicious(video_path):
            os.remove(video_path)
            raise ValueError(f"{video_id}:finalize_video: Malicious Video Upload Attempt")

        rootLogger.debug(f'{video_id}:finalize_video: Retrieving video frame info...')
        fps, total_frames = get_video_info(video_path)  
        max_num_frames = 10*fps
        num_frames_mapping = (total_frames*100)/max_num_frames
        extract_number = math.ceil(total_frames/num_frames_mapping)
        rootLogger.debug(f'{video_id}:finalize_video: Video fps={fps}, total_frame={total_frames}, max_num_frames={max_num_frames}, num_frames_mapping={num_frames_mapping}, extract_number={extract_number}')
    
        # Call function to extract frames from the finalized video
        rootLogger.debug(f'{video_id}:finalize_video: Extracting frames from {finalized_video_path}/final.mp4 into {finalized_video_path}/frames, with extraction_number={extract_number}')
        extract_frames(finalized_video_path, "final", "mp4", extraction_num = extract_number)

        # Need to iterate over frames and save on blue background
        dpi=300
        cover_width_inches = 4.1338582677
        cover_height_inches = 2.9232283465
        pixel_width = int(cover_width_inches*dpi)
        pixel_height = int(cover_height_inches*dpi)
        blue = (176, 224, 230)

        
        rootLogger.debug(f'{video_id}:finalize_video: Placing frames on blue background...')
        frames_dir = f'{finalized_video_path}/frames'
        for item in os.listdir(frames_dir):
            cover = Image.new('RGB', (pixel_width, pixel_height), blue)
            draw = ImageDraw.Draw(cover)
            item_path = os.path.join(frames_dir, item)
            # Save Image on right side of cover where the image is scaled down to have a height of pixel height
            frame = Image.open(item_path)
            
            new_size = (pixel_height, pixel_height)
            
            # Resize the frame image
            frame = frame.resize(new_size, Image.LANCZOS)
            
            # Calculate the position to paste the frame on the right side of the cover
            position = (pixel_width - pixel_height, 0)
            
            # Paste the frame onto the cover
            cover.paste(frame, position)
            
            cover.save(item_path)


        rootLogger.debug(f'{video_id}:finalize_video: Removing unecessary files...')

        if os.path.exists(f'{video_dir}/frames'):
            shutil.rmtree(f'{video_dir}/frames')
        if os.path.exists(f'{video_dir}/frames_to_return'):    
            shutil.rmtree(f'{video_dir}/frames_to_return')
        if os.path.exists(f'{video_dir}/processed_video.mp4'):   
            os.remove(f'{video_dir}/processed_video.mp4')
        if os.path.exists(f'{video_dir}/trimmed_video.mp4'):  
            os.remove(f'{video_dir}/trimmed_video.mp4')

        dpi=300
        cover_width_inches = 4.1338582677
        cover_height_inches = 2.9232283465
        pixel_width = int(cover_width_inches*dpi)
        pixel_height = int(cover_height_inches*dpi)
        blue = (176, 224, 230)
        rootLogger.debug(f'{video_id}:finalize_video: Creating cover, width={pixel_width}, height={pixel_height}')

        cover = Image.new('RGB', (pixel_width, pixel_height), blue)

        # Create a drawing context
        draw = ImageDraw.Draw(cover)

        # Load font
        title_font_size = 90
        title_font = ImageFont.truetype(FONT, title_font_size)
        orange = (255, 129, 79)

        # Calculate text size and position for the title
        rootLogger.debug(f'{video_id}:finalize_video: Calculate text size and position for the title')
        title_text = video_details.title
        title_height = title_font_size
        title_width = draw.textlength(title_text, font=title_font)
        title_x = (pixel_width - title_width) // 2
        title_y = (pixel_height - title_height) // 2 - 42

        # Draw the title text
        rootLogger.debug(f'{video_id}:finalize_video: Drawing the title text')
        draw.text((title_x, title_y), title_text, fill=orange, font=title_font)

        # Load smaller font for website.com
        website_font_size = 35
        website_font = ImageFont.truetype(FONT, website_font_size)

        # Calculate text size and position for website.com
        rootLogger.debug(f'{video_id}:finalize_video: Calculating text size and position for website.com')
        website_text = 'createaflipbook.com'
        website_width = draw.textlength(website_text, font=website_font)
        space_between_texts = 20  # Space between title and website.com
        website_x = (pixel_width - website_width) // 2
        website_y = title_y + title_height + space_between_texts

        # Draw the website text
        draw.text((website_x, website_y), website_text, fill=orange, font=website_font)

        # Function to draw dashed line
       
        
        rootLogger.debug(f'{video_id}:finalize_video: Drawing dashed lines and logo on cover')
        # Define the positions for the dashed lines
        top_right_start = (pixel_width - 300, 0)
        top_right_end = (pixel_width, 300)

        bottom_left_start = (0, pixel_height - 300)
        bottom_left_end = (300, pixel_height)

        # Draw the dashed lines
        draw_dashed_line(draw, top_right_start, top_right_end, color=orange)
        draw_dashed_line(draw, bottom_left_start, bottom_left_end, color=orange)

        # Load and place the logo
        logo = Image.open(LOGO)

        logo.thumbnail((130, 130))

        # Calculate position to place the logo in the top right corner
        logo_x = pixel_width - logo.width - 10  # 10 pixels padding from the right edge
        logo_y = 10  # 10 pixels padding from the top edge

        # Paste the logo onto the cover
        cover.paste(logo, (logo_x, logo_y), logo)


        left_book_cover = cover.copy()
        right_book_cover = cover.copy()

        rootLogger.debug(f'{video_id}:finalize_video: Creating full front-back cover')

        # Create full front-back cover
        num_pages = count_files(f'{finalized_video_path}/frames')
        pixel_width = int(cover_width_inches*dpi*2+(num_pages*THICKNESS_PER_PAGE*dpi))
        front_back_cover = Image.new('RGB', (pixel_width, pixel_height), blue)

        left_margin = 0  
        right_margin = front_back_cover.width - cover.width

        # Step 3: Paste the book covers onto the full front-back cover
        front_back_cover.paste(left_book_cover, (left_margin, 0))
        front_back_cover.paste(right_book_cover, (right_margin, 0))

    
        front_back_cover.save(f'{finalized_video_path}/frames/cover_page.png')

        # first page
        pixel_width = int(cover_width_inches*dpi)
        cover = Image.new('RGB', (pixel_width, pixel_height), blue)


        # Create a drawing context
        draw = ImageDraw.Draw(cover)

        rootLogger.debug(f'{video_id}:finalize_video: Write inner message')

        # Load font
        title_font_size = 90
        title_font = ImageFont.truetype(FONT, title_font_size)
        orange = (255, 129, 79)

        # Calculate text size and position for the title
        title_text = video_details.message
        max_characters_per_line = 15
        title_text_words = title_text.split(' ')
        edited_title_text = ""

        for word in title_text_words:
            if len(edited_title_text.split('\n')[-1])+len(word)<max_characters_per_line:
                edited_title_text +=f'{word} '
            else:
                edited_title_text=edited_title_text[:len(edited_title_text)-1]+"\n"+word+' '

        edited_title_text = edited_title_text[:-1]

        
        text_left, text_top, text_right, text_bottom = draw.multiline_textbbox(xy=[0,0], text=edited_title_text, font=title_font, align="center")
        title_x = (pixel_width - (text_right-text_left)) // 2 + 50
        title_y = (pixel_height - (text_bottom-text_top)) // 2

        # Draw the title text
        draw.text((title_x, title_y), edited_title_text, fill=orange, font=title_font, align='center')
        
       
        cover.save(f'{finalized_video_path}/frames/inner_message.png')

        rootLogger.debug(f'{video_id}:finalize_video: Creating print pages')

        os.makedirs(f'{finalized_video_path}/print_pages')
        image_paths = [os.path.join(f'{finalized_video_path}/frames', f) for f in os.listdir(f'{finalized_video_path}/frames') if f != 'cover_page.png']


        image_paths.sort(key=extract_number_sort)
        page_width, page_height = A4
        image_width = page_width / 2  # Assuming equal widths for images
        image_height = page_height / 4  # Assuming equal heights for images


        for i in range(0, len(image_paths), 8):
            end_index = min(i + 8, len(image_paths))
            image_files = image_paths[i:end_index]
            
            c = canvas.Canvas(f'{finalized_video_path}/print_pages/page_{i}.pdf', pagesize=A4)
            
            for i, path in enumerate(image_files):
                row = i // 2  # Determine row index
                col = i % 2   # Determine column index
                x = col * image_width
                y = page_height - (row + 1) * image_height  # Calculate y-coordinate from top

                # Draw the image on the canvas
                c.drawImage(path, x, y, width=image_width, height=image_height)

            # Save the PDF document
            c.save()


        cover_page = f'{finalized_video_path}/print_pages/cover_page.pdf'

        # Create a canvas and specify A4 size in landscape orientation
        c = canvas.Canvas(cover_page, pagesize=landscape(A4))

        # Calculate dimensions of A4 in landscape mode
        width, height = landscape(A4)

        # Load the image
        im = ImageReader(f'{finalized_video_path}/frames/cover_page.png')

        # Calculate image dimensions
        im_width, im_height = im.getSize()

        # Calculate the desired height (1/4 of the width)
        desired_height = width / 4

        # Calculate scaling factor based on the desired height
        scale = desired_height / im_height

        # Draw the image on the canvas
        c.drawImage(im, 0, 0, im_width * scale, im_height * scale)


        c.save()
        execution_time = time.time()-start_time
        rootLogger.info(f'{video_id}:finalize_video: Exiting /finalize_video with status 200, after {execution_time} seconds')
        response.status_code=200
        return {"detail": "Video finalized successfully"}
    
    except Exception as e:
        rootLogger.debug(f'{video_id}:finalize_video: Error 500 Unexpected Error: {str(e)}', stacklevel=2)
        raise HTTPException(status_code=500, detail=f"Internal Server Error")
    

def verify_token(token):
    try:
        decoded = jwt.decode(token, os.getenv('JWT_SECRET'), algorithms=["HS256"])
        return decoded
    except jwt.ExpiredSignatureError:
        raise Exception("Token has expired")
    except jwt.InvalidTokenError:
        raise Exception("Invalid token")



def get_files_by_id(order_id):
    directory_path = f"{VIDEO_DIR}/{order_id}/finalized_video/print_pages"

    if not os.path.exists(directory_path):
        raise FileNotFoundError(f"Directory {order_id} does not exist")

    files = []
    for filename in os.listdir(directory_path):
        file_path = os.path.join(directory_path, filename)
        files.append(file_path)
    files.sort() 
    return files




class DownloadFilesDetails(BaseModel):
    id: str


@app.post("/download_files")
async def download_files(video_details: DownloadFilesDetails, authorization: str = Header(None)):
    try:
        rootLogger.info(f'(MANAGEMENT) {video_details.id}:download_files: Received request to download for id={video_details.id}')
        if not authorization:
            rootLogger.debug(f'(MANAGEMENT) {video_details.id}:download_files: No authorization header received')
            raise HTTPException(status_code=401, detail="Missing authorization token")
        
        token = authorization.split(' ')[1]  # Assuming format "Bearer <token>"
        decoded_token = verify_token(token)
        if decoded_token['sub'] == os.getenv('ADMIN_LOGIN_USER_NAME'):
            rootLogger.debug(f'(MANAGEMENT) {video_details.id}:download_files: Token verified successfully')
            order_id = video_details.id
            files_to_print = get_files_by_id(order_id)
            
            zip_buffer = BytesIO()
            with zipfile.ZipFile(zip_buffer, 'w') as zip_file:
                for file_path in files_to_print:
                    if os.path.exists(file_path):
                        zip_file.write(file_path, os.path.basename(file_path))
                    else:
                        raise HTTPException(status_code=404, detail=f"File not found")
            zip_buffer.seek(0)
            rootLogger.debug(f'(MANAGEMENT) {video_details.id}:download_files: Returning streaming response')
            return StreamingResponse(zip_buffer, media_type='application/zip', headers={"Content-Disposition": f"attachment; filename={order_id}_files.zip"})
        else:
            rootLogger.debug(f'(MANAGEMENT) {video_details.id}:download_files: Token failed verification')
            raise HTTPException(status_code=403, detail="Invalid credentials")
    except Exception as e:
        rootLogger.debug(f'(MANAGEMENT) {video_details.id}:download_files: An unexpected error occurred: {str(e)}', stacklevel=2)
        raise HTTPException(status_code=500, detail="Internal Server Error")


def days_since_modified(modified_time):
    now = datetime.now()
    modified_datetime = datetime.fromtimestamp(modified_time)
    delta = now - modified_datetime
    return delta.days



@app.get("/videos")
async def list_videos(response: Response, authorization: str = Header(None)):
    try:
        if not authorization:
            rootLogger.debug(f'(MANAGEMENT) list_videos No authorization header received')
            raise HTTPException(status_code=401, detail="Missing authorization token")
        
        token = authorization.split(' ')[1]  # Assuming format "Bearer <token>"
        decoded_token = verify_token(token)
        if decoded_token['sub'] == os.getenv('ADMIN_LOGIN_USER_NAME'):
            rootLogger.debug(f'(MANAGEMENT) list_videos: Token verified successfully')
            folder_details = []
            
            for folder_name in os.listdir(VIDEO_DIR):
                folder_path = os.path.join(VIDEO_DIR, folder_name)
                if os.path.isdir(folder_path):
                    last_modified_time = os.path.getmtime(folder_path)
                    days_since_modification = days_since_modified(last_modified_time)
                    folder_details.append({
                        "id": folder_name,
                        "days_since_modified": days_since_modification
                    })
            rootLogger.debug(f'(MANAGEMENT) list_videos: Returning videos')
            return {"videos": folder_details}
        else:
            rootLogger.debug(f'(MANAGEMENT) list_videos Token failed verification')
            raise HTTPException(status_code=403, detail="Invalid credentials")
    except Exception as e:
        rootLogger.debug(f'(MANAGEMENT) list_videos: An unexpected error occurred: {str(e)}', stacklevel=2)
        raise HTTPException(status_code=500, detail="Internal Server Error")
    

class DeleteVideoDetails(BaseModel):
    video_id: str

@app.delete("/videos")
async def delete_video(video_details: DeleteVideoDetails, response: Response, authorization: str = Header(None)):
    try:
        rootLogger.info(f'(MANAGEMENT) {video_details.video_id}:delete_video: Received request to delete for id={video_details.video_id}')
        if not authorization:
            rootLogger.debug(f'(MANAGEMENT) {video_details.video_id}:delete_video: No authorization header received')
            raise HTTPException(status_code=401, detail="Missing authorization token")
        
        token = authorization.split(' ')[1]  # Assuming format "Bearer <token>"
        decoded_token = verify_token(token)
        if decoded_token['sub'] == os.getenv('ADMIN_LOGIN_USER_NAME'):
            rootLogger.debug(f'(MANAGEMENT) {video_details.video_id}:delete_video: Token verified successfully')
            directory_path = f"{VIDEO_DIR}/{video_details.video_id}"
            shutil.rmtree(directory_path)
            rootLogger.debug(f'(MANAGEMENT) {video_details.video_id}:delete_video: Video deleted successfully')
            return {"message": "success"}
        else:
            rootLogger.debug(f'(MANAGEMENT) l{video_details.video_id}:delete_video: Token failed verification')
            raise HTTPException(status_code=403, detail="Invalid credentials")
    except Exception as e:
        rootLogger.debug(f'(MANAGEMENT) {video_details.video_id}:delete_video: An unexpected error occurred: {str(e)}', stacklevel=2)
        raise HTTPException(status_code=500, detail="Internal Server Error")
    


if __name__ == "__main__":
    uvicorn.run(app, host=HOST, port=PORT)