import psutil
import os
import socket
import pyDHE
import sys
import time
from threading import *
import base64
from time import strftime, localtime
from PyQt5 import QtWidgets, uic

from aead import AEAD
from random import randint


### GLOBAL FUNCTIONS ###
def timed():
    return(strftime("%H:%M:%S", localtime()))


def formatResult(color="black", text=""):
    return ('<font color="{0}">[{1}] {2}</font>'.format(color, timed(), text))


def exit_program():
    me = os.getpid()
    sys.exit(kill_proc_tree(me))


def kill_proc_tree(pid, including_parent=True):
    parent = psutil.Process(pid)
    if including_parent:
        parent.kill()

# main flow of program:
# start > mainChat > ChatThread


class start(QtWidgets.QMainWindow):
    def __init__(self, parent=None):
        super(start, self).__init__()
        uic.loadUi('UI/login.ui', self)
        self.show()
        self.dialogs = list()
        self.connectbutton.clicked.connect(self.Login)
        self.closebutton.clicked.connect(exit_program)

    def Login(self):
        global nickname
        global secret
        global serverAddr
        global portNum
        
        nickname = self.nicknamefield.text()
        secret = self.passwordfield.text()
        serverAddr = self.addrfield.text()
        portNum = int(self.portfield.text())

        server = serverAddr + ":" + str(portNum)

        # with login details, start thread
        dialog = mainChat()
        chatThread = ChatThread(dialog, server, nickname)
        chatThread.start()
        self.dialogs.append(dialog)
        dialog.show()
        self.close()


class mainChat(QtWidgets.QMainWindow):
    def __init__(self, parent=None):
        super(mainChat, self).__init__(parent)
        uic.loadUi('UI/chatroom.ui', self)

        # setting up the UI; assigning functions to elements
        self.sendButton.clicked.connect(self.send_msg)

        self.textEdit.setReadOnly(True)
        self.textEdit.insertHtml(formatResult(
            color="blue", text="Trying to connect server {}".format(serverAddr)))

        self.actionHome.triggered.connect(self.backHome)
        self.actionExit.triggered.connect(exit_program)

    def send_msg(self):
        # first format the message and then encrypt it before sending to socket
        msg = self.lineEdit.text()
        message = '{}: {}'.format(nickname, msg)
        ct = cryptor.encrypt(bytes(message, 'utf-8'),
                             bytes(secret, "utf-8"))
        client.send(ct)
        self.lineEdit.setText("")

    def backHome(self):
        # closes the current socket and returns to the login page
        client.close()
        time.sleep(1)
        self.loginwindow = start()
        self.close()


class ChatThread(Thread):
    def __init__(self, window, host, name):
        Thread.__init__(self)
        self.window = window
        self.host = host
        self.name = name
        self.state = False
        self.window.label.setText(" "+self.name+":  ")

    def run(self):
        self.window.sendButton.setEnabled(False)

        # setting up client socket and connecting to server
        global client
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client.connect((serverAddr, portNum))
        except:
            self.window.textEdit.append(formatResult(
                color="red", text="Failed connect to server"))
            self.state = True

        # create ECDH public key
        ecdh = pyDHE.new()
        ecdhPubKey = ecdh.getPublicKey()
        print("Initialising, please wait... (Do not enter any inputs)")
        # print("MY ECDH: ", ecdhPubKey)

        global cryptor
        while not self.state:
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
                    keyString = message.split(":")
                    opposingPubKey = keyString[1]

                    # if public key is different then negotiate ECDH shared key
                    if str(opposingPubKey) != str(ecdhPubKey):
                        try:

                            sharedKey = ecdh.update(int(opposingPubKey))
                            # print("SHARED KEY: ", str(sharedKey))

                            init_byte_value = len(str(sharedKey))
                            sharedKey = init_byte_value.to_bytes(
                                32, byteorder='little')

                            cryptor = AEAD(base64.urlsafe_b64encode(sharedKey))
                            self.window.textEdit.append(formatResult(
                                color="green", text="Initialising complete! You may proceed to chat"))
                            self.window.sendButton.setEnabled(True)

                        except:
                            self.window.textEdit.append(formatResult(
                                color="red", text="Key exchange error! Please reconnect again!"))
                            self.window.sendButton.setEnabled(False)
                            self.state = True
                            client.close()

                elif nickname in message:
                    self.window.textEdit.append(formatResult(text=message))

                elif "Connected to server!" in message:
                    self.window.textEdit.append(formatResult(text=message))

                elif "joined!" in message:
                    self.window.textEdit.append(formatResult(text=message))

                elif "left!" in message:
                    self.window.textEdit.append(formatResult(text=message))

                elif "Chat room full." in message:
                    self.window.textEdit.append(formatResult(text=message))

                elif "ALIVE" in message:
                    pass

                else:
                    try:
                        pt = cryptor.decrypt(message, bytes(secret, "utf-8"))
                        self.window.textEdit.append(
                            formatResult(text=pt.decode("utf-8")))
                        print(pt.decode("utf-8"))

                    except ValueError:
                        self.window.textEdit.append(
                            formatResult(color="red", text="Error!"))
                        self.window.textEdit.append(formatResult(
                            color="red", text="It may be due one of the following reasons: "))
                        self.window.textEdit.append(formatResult(
                            color="red", text="1. Incorrect shared secret."))
                        self.window.textEdit.append(formatResult(
                            color="red", text="2. The other party left the chat."))
                        self.window.textEdit.append(formatResult(
                            color="red", text="3. The server closed the connection"))
                        self.window.textEdit.append(formatResult(
                            color="red", text="Please try to reconnect again!"))
                        self.window.sendButton.setEnabled(False)

                    except:
                        self.window.textEdit.append(formatResult(
                            color="red", text="Session terminated! Exiting!"))
                        self.window.sendButton.setEnabled(False)
                        self.state = True
                        client.close()

            except:
                self.window.textEdit.append(formatResult(
                    color="yellow", text="Connection to the server has ended."))
                self.state = True
                self.window.sendButton.setEnabled(False)
                client.close()


# start the app by running the login page.
app = QtWidgets.QApplication(sys.argv)
window = start()
app.exec_()
me = os.getpid()
sys.exit(kill_proc_tree(me))
