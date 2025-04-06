import os
from pytube import Playlist, YouTube
from tqdm import tqdm
from pathlib import Path
from tkinter import Tk
from tkinter.filedialog import askdirectory

def select_download_folder():
    Tk().withdraw()
    folder = askdirectory(title="Select Download Folder")
    return folder if folder else os.getcwd()

def download_video(video: YouTube, download_path: Path):
    stream = video.streams.filter(progressive=True, file_extension='mp4').get_highest_resolution()
    filesize = stream.filesize

    print(f"\n📥 Downloading: {video.title}")
    with tqdm(total=filesize, unit='B', unit_scale=True, desc=video.title[:30], ncols=100) as pbar:
        def progress_callback(stream, chunk, bytes_remaining):
            pbar.update(len(chunk))

        video.register_on_progress_callback(progress_callback)
        stream.download(output_path=download_path)

def download_playlist(playlist_url: str):
    try:
        playlist = Playlist(playlist_url)
        print(f"\n🔗 Playlist found: {playlist.title}")
        print(f"🎵 Total videos: {len(playlist.video_urls)}")

        download_path = Path(select_download_folder())
        print(f"📁 Download location: {download_path}\n")

        for url in playlist.video_urls:
            video = YouTube(url)
            download_video(video, download_path)

        print("\n✅ All videos downloaded successfully!")

    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    print("📺 YouTube Playlist Downloader")
    playlist_url = input("🔹 Enter the playlist URL: ").strip()
    download_playlist(playlist_url)
