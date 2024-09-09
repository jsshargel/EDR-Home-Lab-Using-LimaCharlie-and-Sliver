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
- 
<img width="779" alt="Screenshot 2024-09-09 090548" src="https://github.com/user-attachments/assets/ed24d8de-9bb5-490c-85ca-1d35b5b8acf9">

#



