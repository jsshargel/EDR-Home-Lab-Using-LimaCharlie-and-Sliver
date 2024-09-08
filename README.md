# Home-SOC-Analyst-Lab
# Configuration
- First, we need to download VMware.
- Second, let's download an ISO from: https://releases.ubuntu.com/22.04.1/ubuntu-22.04.1-live-server-amd64.iso
- Next, let's create a VM using that ISO.
- We can select a typical installation and then find and select the ISO to continue.
- If you want you can change the Maximum disk size to 14GB and then continue.
- Before we finish up let's customize the hardware by changing the memory to 2GB.
- Ok, now we can finish up and Install the ISO.
<img width="791" alt="Screenshot 2024-09-08 130029" src="https://github.com/user-attachments/assets/5f2c8631-3c3d-4cbc-97b4-9671034bf5bd">

#

- Next up, we'll have to run through some options during the OS install.
- I selected English and on the next screen continued without updating.
- Make sure Ubuntu Server is selected and continue.
- When we get to network connections we need to set up a static IP Address.
- This will ensure that the IP address for this VM won't charge during the entirety of this lab.
- In the VMware workstation click edit and then select virtual network editor.
- Select NAT and then Nat settings.
- In NAT settings take note of the Subnet IP and the Gateway IP.
- Now we need to head back over to the installation.
- Once there, we need to manually edit the IPv4 information.
 <img width="635" alt="Screenshot 2024-09-08 133843" src="https://github.com/user-attachments/assets/d0df8011-a7fd-49c1-8e8c-ffded6352414">

 #

- Go ahead and enter the Subnet IP Address that you copied down before and make sure to add /24 at the end of the address.
- Next, for the address, we'll use the address from the previous screen under DHCPv4. Just make sure not to include /24 this time.
- Next, enter the Gateway IP copied from earlier.
- Finally, enter 8.8.8.8 under Name Server.
- We can leave the search domains blank and then save these settings.
 <img width="632" alt="Screenshot 2024-09-08 134022" src="https://github.com/user-attachments/assets/8bc807f1-bd14-4fcf-b998-6e40e434247e">

 #

- Copy down the static IP address and then continue.
- Next, continue through the options until you get to the profile setup.
- Once there select your username and password etc.
- Continue forward and make sure to install OpenSSH.
- After this continue until you can install the OS.
<img width="638" alt="Screenshot 2024-09-08 140000" src="https://github.com/user-attachments/assets/158d1619-c960-4532-94d6-5371e903fd39">
