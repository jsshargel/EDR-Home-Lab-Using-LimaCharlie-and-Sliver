# Home-SOC-Analyst-Lab
- Head over to Eric Escapuanos's guide for step-by-step instructions on this lab.
- https://blog.ecapuano.com/p/so-you-want-to-be-a-soc-analyst-part
# Configuration

- The first steps of this lab will be downloading VMware and creating our Virtual Machines. There will be two virtual machines. We will run an Ubuntu Server VM that will serve as the attacker and a Windows VM that will serve as the endpoint. We also need to make the Windows VM vulnerable. To do that we will disable Microsoft Defender and change some settings to ensure that it does not turn back on.

<img width="629" alt="Screenshot 2024-09-08 140212" src="https://github.com/user-attachments/assets/0417fde6-3d29-4512-bd54-975c9a921eb4">

#

<img width="752" alt="Screenshot 2024-09-09 081252" src="https://github.com/user-attachments/assets/eec36d2f-8caf-4374-bdbe-62e651ef2ab3">

#

- Before we continue let's go ahead and set up sysmon on our Windows VM. Sysmon will provide detailed logging.
- Once we enable sysmon to work alongside LimaCharlies EDR telemetry, we will have a much more comprehensive view of what is happening with the machine.

<img width="754" alt="Screenshot 2024-09-09 083413" src="https://github.com/user-attachments/assets/84f11c87-a5f7-4b25-af3d-853ba13822fa">

#

- After that is finished we will set up a LimaCharlie account and install a sensor onto our endpoint machine. This will enable us to monitor what is happening on our compromised Windows VM. 

<img width="752" alt="Screenshot 2024-09-09 085906" src="https://github.com/user-attachments/assets/5249c2b2-da26-4cc1-87bd-579b62ff8783">

#
 
<img width="518" alt="Screenshot 2024-09-09 085842" src="https://github.com/user-attachments/assets/8ec4e294-a1ec-4bb5-a92e-4473dd063c60">

#

- Now we can set up sysmon to work alongside LimaCharlie.

<img width="779" alt="Screenshot 2024-09-09 090548" src="https://github.com/user-attachments/assets/ed24d8de-9bb5-490c-85ca-1d35b5b8acf9">

#

- For the next step we'll SSH into our attack machine and download Sliver.
- Sliver is an open-source Command and Control (C2) Framework.
- This will be used to create realistic attack scenarios that we can use to detect and remedy via LimaCharlie.
- We will use Sliver to generate the session payload(malware) that will be used to attack the Windows VM.

<img width="489" alt="Screenshot 2024-09-09 094309" src="https://github.com/user-attachments/assets/5ed15473-9237-4ced-8ff6-1cc44eba17e2">

#

- Now we can download the payload on the Windows VM and connect to the session on our attack machine.

<img width="848" alt="Screenshot 2024-09-09 095434" src="https://github.com/user-attachments/assets/162c5c08-251e-407a-b943-b016b8f4bbd7">

#

- Once we are connected we can start to see some interesting things.
- We can use commands such as info, whoami, getprivs, etc to gain information about our victim's machine.

<img width="856" alt="Screenshot 2024-09-09 095618" src="https://github.com/user-attachments/assets/e8a736f6-6d21-42f3-b4c8-6f91142f88cf">

#

- Sliver has a cool feature that will highlight its process in green and defensive tools in red.
- This is important information for the attackers.

<img width="854" alt="Screenshot 2024-09-09 095819" src="https://github.com/user-attachments/assets/e9a42dba-9fff-47cc-bd75-b94e7dbde2af">

#

<img width="844" alt="Screenshot 2024-09-09 095756" src="https://github.com/user-attachments/assets/b8734c76-3c7c-4d78-817c-a96f1381d178">

#

- Let's head back over to LimaCharlie and observe the telemetry to see what has happened.
- Let's navigate to the Windows Sensor we created and open processes.
- In this case, we can easily spot the payload because it does not have a valid signature.
- We can also see crucial information such as the path of the process and network connections
<img width="782" alt="Screenshot 2024-09-09 103028" src="https://github.com/user-attachments/assets/691f43bc-420f-4f35-94b7-48714f80574d">

#

<img width="778" alt="Screenshot 2024-09-09 103144" src="https://github.com/user-attachments/assets/c073999c-d665-427c-b6e0-16634d5f2142">

#

<img width="785" alt="Screenshot 2024-09-09 102943" src="https://github.com/user-attachments/assets/c64311b8-c48c-4d26-8512-a6013ec6d24b">

#

- Let's search the file system location where we know the payload to be and go a step further.
- When we find it here we can use virustotal to scan the hash of the EXE. If it has seen the has before it will be detected.
- In this case, we come up with nothing because we made this ourselves. 

<img width="782" alt="Screenshot 2024-09-09 103314" src="https://github.com/user-attachments/assets/92532026-4066-488f-930f-a2c29d4d6d5d">

#

<img width="407" alt="Screenshot 2024-09-09 103332" src="https://github.com/user-attachments/assets/7fb10e66-753e-4719-af14-9e3e44c70e5d">

#

<img width="449" alt="Screenshot 2024-09-09 103354" src="https://github.com/user-attachments/assets/9e55a53c-fe14-43b4-897e-7023ab2e8237">

#

- Let's move on to the timeline.
- The timeline will show us real-time EDR telemetry and event logs!

<img width="788" alt="Screenshot 2024-09-09 104818" src="https://github.com/user-attachments/assets/591d817e-4680-416f-9a33-428e38660743">

#

- Next, from Sliver we'll dump the lsass.exe process from memory. This is something attackers often do to steal credentials.
- Since this is a sensitive process we'll be able to observe the relevant telemetry and figure out what to do from there. 
















