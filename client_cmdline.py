# This is the command line version of the chat application!
import socket
import threading
import pyDHE
import base64
import sys
import time
import signal
import traceback
import getpass
from aead import AEAD
from random import randint

nickname = input("Choose your nickname: ")
secret = getpass.getpass("Enter shared secret for encrypted chat : ")

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('13.67.40.99', 7976))
cryptor = None

# create ECDH public key
ecdh = pyDHE.new()
ecdhPubKey = ecdh.getPublicKey()
print("Initialising, please wait... (Do not enter any inputs)")
# print("MY ECDH: ", ecdhPubKey)
up_one_line = '\x1b[1A'
erase_line = '\x1b[2K'


def receive():
    global cryptor
    while True:
        try:
            message = client.recv(2048).decode('utf-8')
            # print(message)
            if message == 'NICKNAME':
                client.send(nickname.encode('utf-8'))
            elif 'EXCHANGE' in message:
                # once connected, send ecdh public key that was created
                time.sleep(randint(1, 5))
                client.send(bytes("KEY:" + str(ecdhPubKey), 'utf-8'))
            elif 'KEY:' in message:
                # print(message)
                keyString = message.split(":")
                opposingPubKey = keyString[1]

                # if public key is different then negotiate ECDH shared key
                if str(opposingPubKey) != str(ecdhPubKey):
                    try:
                        #print("OPP ECDH: ", opposingPubKey)
                        #print(str(opposingPubKey).isdigit(), type(opposingPubKey))

                        sharedKey = ecdh.update(int(opposingPubKey))
                        #print("SHARED KEY: ", str(sharedKey))

                        init_byte_value = len(str(sharedKey))
                        sharedKey = init_byte_value.to_bytes(
                            32, byteorder='little')

                        cryptor = AEAD(base64.urlsafe_b64encode(sharedKey))

                        print("Initialising complete! You may proceed to chat")

                    except:
                        print("Key exchange error! Please reconnect again!")
                        exit_program()

            elif nickname in message:
                print(message)

            elif "Connected to server!" in message:
                print(message)

            elif "joined!" in message:
                print(message)

            elif "left!" in message:
                print(message)

            elif "Chat room full." in message:
                print(message)

            elif "ALIVE" in message:
                pass

            else:
                try:
                    pt = cryptor.decrypt(message, bytes(secret, "utf-8"))
                    print(pt.decode("utf-8"))
                    if nickname in pt.decode("utf-8"):
                        quit_string = pt.decode("utf-8").split(": ")
                        if "quit" == quit_string[1]:
                            print("Quit command issued. Exiting...!")
                            exit_program()
                            break

                except ValueError:
                    print("\nError!")
                    print("It may be due one of the following reasons: ")
                    print("1. Incorrect shared secret.")
                    print("2. The other party left the chat.")
                    print("3. The server closed the connection")
                    print("Please try to reconnect again!")
                    exit_program()
                    break

                except:
                    print("Session terminated! Exiting!")
                    exit_program()
                    break

        except:
            print("Thank you! Good bye! Press enter to exit.")
            exit_program()
            break


def write():
    while True:
        try:
            msg_input = input("")
            message = '{}: {}'.format(nickname, msg_input)
            ct = cryptor.encrypt(bytes(message, 'utf-8'),
                                 bytes(secret, "utf-8"))
            client.send(ct)
            sys.stdout.write(up_one_line)
            sys.stdout.write(erase_line)

        except:
            exit_program()
            break


def exit_program():
    client.close()
    time.sleep(1)
    sys.exit()


try:
    receive_thread = threading.Thread(target=receive)
    receive_thread.start()
    write_thread = threading.Thread(target=write)
    write_thread.start()
    write_thread.join()
    receive_thread.join()
except KeyboardInterrupt:
    exit_program()
