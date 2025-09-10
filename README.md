# MANTIS

<img src="https://github.com/user-attachments/assets/701020ba-2b18-4bf0-805e-ee75a211d7ed"> 

## What is Mantis?

<b>Mantis is a monitoring tool built to monitor files, tasks, and requests sent from your system!

With this tool, you can understand how an exe file behaves with your files, what tasks it creates or closes, what requests it sends to where with what data!

This tool is released as open source and you can use it for free!</b> 

<img src="https://github.com/user-attachments/assets/15c672ff-97ab-4737-b8ad-79f9fbd034d8">

<a href="https://github.com/Mr-Spect3r/MANTIS/releases">To download and view new versions or exe files, go to this section</a>

<details>
  <summary><strong>What does mantis mean?</strong></summary>
  <p>Monitoring All Network, Tasks, and Integrated Systems</p>
</details>

<details>
  <summary><strong>Features</strong></summary>
  
   - File Monitoring (You can see what files/folders have been created, edited, or deleted)</p> 
   
   - Process Monitoring (You can see which tasks were created by which program, which tasks are opened, and which tasks are currently running.)</p> 
   
   - Network Monitoring
</details>


<details>
  <summary><strong>Why did I create Mantis?</strong></summary>
  
   - I designed this tool for analyzing programs

   - You can read it here:<a href="https://github.com/Mr-Spect3r/MANTIS/blob/main/writeup.md"> WriteUp
</details>


<details>
  <summary><strong>Prerequisites</strong></summary>
  
   - Libraries

```
psutil
pydivert
watchdog
customtkinter
graphviz
Pillow
queue
pyqtgraph
PySide6
```

   - install graphviz (for use graph)

Open Powershell and Type: `winget install graphviz`

- and set address in System:

Open Environment Variables:

Right-click This PC → Properties → Advanced system settings → Environment Variables

Edit PATH:

Under System variables, select Path → Edit → New → add the folder path (e.g., C:\Program Files\Graphviz\bin) → OK

Apply & Test:

<img src="https://github.com/user-attachments/assets/eb8e2f02-b228-4ac4-988b-17b3176ae543">

Close all dialogs, open a new terminal, and run:

`dot -V`


You should see the Graphviz version.

I can also give a super concise 3-line version for quick reference if you want.

</details>

## Help


- File Monitoring Section

In this section, you can specify a path, then click the monitoring button, (make sure the program you want is in the same path) From now on, any activity related to files your program has will be logged for you! File creation, file deletion, file update (edit) and file transfer


- Process Monitoring Section

You all have experience using Task Manager! This section makes your work easier! By clicking this button, a window with 4 sections will open for you, in these 4 sections you can see what files are running, what tasks were created by which programs, what tasks were closed, the list of closed Task

- Network Monitoring Section

In this section, you can see all the files, what requests, from which program, to where, with what data they are sent! You can almost understand what is happening behind the scenes of the program!

- How to Run:

```
git clone https://github.com/Mr-Spect3r/MANTIS
cd MANTIS
pip install -r requirements.txt
python MANTIS.py
```

File Exe: <a href="https://github.com/Mr-Spect3r/MANTIS/releases/download/MANTIS/MANTIS.exe)">Download

# ScreenShots

- Process Monitor

<img src="https://github.com/user-attachments/assets/7e31deea-5787-45c1-ab99-68b9d7552f2d">

- Network Monitor

<img src="https://github.com/user-attachments/assets/0db87f42-8c77-4808-a0af-d25005b14831">


# New version 1.3.1

<img src="https://github.com/user-attachments/assets/74d0e58e-cc00-446b-a952-535af7fc3d65">
