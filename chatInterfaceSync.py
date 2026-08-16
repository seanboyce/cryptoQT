from time import sleep
import fnmatch
import serial
import glob
menu_enabled = True

# This is a simple synchronous driver for the hardware, sufficient for testing and sending simple messages. Ideally, it would at least asynchronously catch message events by the serial port sending 0x07, and drain the buffer in the hardware, which only stores 3 messages. 

def menu():
    print(
"""Main Menu:
1: Connect to remote device
2: Send message
3: Halt and restart
4: Return pending messages
5: Accept chat request
6: Return local identifier
7: Return remote identifier (if connected)
8: Config (not implemented)

""")

def auto_detect_serial_unix(preferred_list=['*']):
    '''try to auto-detect serial ports on posix based OS'''
    glist = glob.glob('/dev/ttyUSB*') + glob.glob('/dev/ttyACM*') #It is sometimes practical to remove one of these, e.g. if you have other serial devices
    ret = []
    # try preferred ones first
    for port in glist:
        ret.append(port)
    return ret

def command(port, keypress):
    match keypress:
        case "1":
            userInput = input("Enter the remote indentifier:")
            userInput = userInput.strip()
            if len(userInput) != 16:
                print("Invalid identifier, command cancelled.")
                print(userInput)
                print(len(userInput))
            else:
                print("Connecting to: " + str(userInput))
                port.write(b'\x01')
                #time.sleep(0.1)
                port.write(userInput.encode('ascii'))
                print(userInput.encode('ascii'))
                port.write(b'\x03')
        case "2":
            # Maybe add a check if connected here
            userInput = input("Enter message: ")
            userInput = userInput.strip()
            port.write(b'\x02')
            if port.in_waiting:
                ready = port.read(1)
                print(ready)
            port.write(userInput.encode('ascii'))
            print(userInput.encode('ascii'))
            port.write(b'\x03')
        case "3":
            print("System is restarting.")
            port.write(b'\x04')
            data = port.read_until(b'\x11')
            print("Restart complete.")
        case "4":
            port.write(b'\x05')
            message = bytearray(port.read_until(b'\x03'))
            start = message.find(b"2")
            finish = message.find(b"3")
            message = str(message[start+1:finish], 'ascii')
            print(message)
        case "5":
            port.write(b'\x06')
            data = str(port.read_until(b'\x03')[-17:-1],'ascii')
            userInput = input("Accept this request? y/n")
            if userInput == "y":
                port.write(b'\x06')
                print("Exchanging keys...")
                data = port.read_until(b'\x11')
                print("Success.")
            else:
                port.write(b'\x18') # Replying anything but 0x06 cancels
                
        case "6":
            port.write(b'\x07')
            data = str(port.read_until(b'\x03')[-17:-1],'ascii')
            if len(data) == 0:
                print("No local identifier yet, you may not be connected to WiFi. Wait a moment and try again or check your credentials.")
            print(data)
        case "7":
            port.write(b'\x08')
            data = str(port.read_until(b'\x03')[-17:-1],'ascii')
            if len(data)>15:
                print(data)
            else:
                print("No remote device connected")
        case "8":
            # port.write(b'\x1A')
            pass # Config not implemented yet
        case _:
            print("invalid selection")
    return

try:
    available_ports = auto_detect_serial_unix()
    firstport = 0
    for i in available_ports:
        print(str(firstport) + str(i))
        firstport = firstport + 1
    selectedPort = input("Select a port: ")
    print(available_ports[int(selectedPort)])
    port = serial.Serial(available_ports[int(selectedPort)], 115200,timeout=1)
except:
    raise Exception("No serial port, or port in use")


while True:
    menu()
    option = input()
    command(port, option)
