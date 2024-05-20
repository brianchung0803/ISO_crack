import pandas as pd

class package():
    def __init__(self):
        self.id = None
        self.exec = None
        self.execComment = None
        self.rtn = None
        self.rtnComment = None

class ISO_parser():
    def __init__(self,file):
        xls = pd.ExcelFile(file)
        sheets = xls.sheet_names

        dfs = {}
        for sheet in sheets:
            dfs[sheet]=pd.read_excel(file,sheet)

        for key, value in dfs.items():
            print(self.msg2hex(value.iat[0,0]))

            print("---------")


        self.INS = {
            '0x44':'Activate File',
            '0xE2':'Append Record',
            '0x24':'Change Reference Data',
            '0xE0':'Create File',
            '0x04':'Deactivate File',
            '0xE4':'Delete File',
            '0x26':'Disable Verification Requirement',
            '0x28': 'Enable Verification Requirement',
            '0xC2':'Envelope',
            '0xC3':'Envelope',
            '0x0E':'Erase Binary',
            '0x0F': 'Erase Binary',
            '0x0C': 'Erase Record',
            '0x82': 'External Authenticate',
            '0x86': 'General Authenticate',
            '0x87': 'General Authenticate',
            '0x46': 'Generate Asymmetric Key Pair',
            '0x84': 'Get Challenge',
            '0xCA': 'Get Data',
            '0xCB': 'Get Data',
            '0xC0':'Get Response',
            '0x88':'Internal Authenticate',
            '0x70': 'Manage Channel',
            '0x22': 'Manage Security Environment',
            '0x10': 'Perform SCQL Operation',
            '0x2A': 'Perform Security Operation',
            '0x12': 'Perform Transaction Operation',
            '0x14': 'Perform User Operation',
            '0xDA':'Put Data',
            '0xDB': 'Put Data',
            '0xB0': 'Read Binary',
            '0xB1': 'Read Binary',
            '0xB2': 'Read Record',
            '0xB3': 'Read Record',
            '0x2C': 'Reset Retry Counter',
            '0xA0': 'Search Binary',
            '0xA1': 'Search Binary',
            '0xA2': 'Search Record',
            '0xA4': 'Select',
            '0xFE': 'Terminate Card Usage',
            '0xE6': 'Terminate DF',
            '0xE8': 'Terminate EF',
            '0xD6': 'Update Binary',
            '0xD7': 'Update Binary',
            '0xDC': 'Update Record',
            '0xDD': 'Update Record',
            '0x20': 'Verify',
            '0x21': 'Verify',
            '0xD0': 'Write Binary',
            '0xD1': 'Write Binary',
            '0xD2': 'Write Record'
        }
        self.SW1 = {"0x90":"Normal Processing",
                    "0x61":"Normal Processing",
                    "0x62":"Warning Processing",
                    "0x63":"Warning Processing",
                    "0x64":"Execution error",
                    "0x65":"Execution error",
                    "0x66":"Execution error",
                    "0x67":"Checking error",
                    "0x68":"Checking error",
                    "0x69":"Checking error",
                    "0x6A":"Checking error",
                    "0x6B":"Checking error",
                    "0x6C":"Checking error",
                    "0x6D":"Checking error",
                    "0x6E":"Checking error",
                    "0x6F":"Checking error"}
        self.SW2 = {
            '90':{'00':"No further qualification"},
            '61':{'XX':"SW2 encodes the number of data bytes still"}
        }

    def SW_Resolve(self, args):
        res =""
        param1 = hex(int(args[0]))
        param2 = hex(int(args[1]))
        res+=self.SW1[param1]
        sw2 = ", "
        if(param1=='0x90'):
            sw2+="No further qualification"
        elif(param1=='0x61'):
            sw2+="SW2 encodes the number of data bytes still available"
        elif(param1=="0x62"):
            if(param2=="0x00"):
                sw2+="No information given"
            elif(param2=="0x81"):
                sw2+="Part of returned data may be corrupted"
            elif (param2 == "0x82"):
                sw2 += "End of file or record reached before reading Ne bytes"
            elif (param2 == "0x83"):
                sw2 += "Selected file deactivated"
            elif (param2 == "0x84"):
                sw2 += "File control information not formatted according to 5.3.3"
            elif (param2 == "0x85"):
                sw2 += "Selected file in termination state"
            elif (param2 == "0x86"):
                sw2 += "No input data available from a sensor on the card"
            else:
                sw2+="Triggering by the card"
        elif (param1 == "0x63"):
            if (param2 == "0x00"):
                sw2 += "No information given"
            elif(param2=="0x81"):
                sw2+="File filled up by the last write"
            else:
                if(param2[2]=='c' or param2[2]=='C'):
                    sw2+=f"Counter from 0 to 15 encoded by {param2[3]}"
        elif (param1 == "0x64"):
            if(param2=="0x00"):
                sw2+="Execution error"
            elif(param2=="0x01"):
                sw2+="Immediate response required by the card"
            else:
                sw2 +="Triggering by the card (see SPEC)"
        elif (param1 == "0x65"):
            if (param2 == "0x00"):
                sw2 += "No information given"
            elif (param2 == "0x81"):
                sw2 += "Memory failure"
        elif (param1 == "0x66"):
            sw2 += "Security-related issues"
        elif (param1 == "0x67"):
            sw2 += "Wrong length; no further indication"
        elif (param1 == "0x68"):
            if (param2 == "0x00"):
                sw2 += "No information given"
            elif (param2 == "0x81"):
                sw2 += "Logical channel not supported"
            elif(param2=="0x82"):
                sw2+="Secure messaging not supported"
            elif(param2=="0x83"):
                sw2+="Last command of the chain expected"
            elif(param2=="0x84"):
                sw2+="Command chaining not supported"
            else:
                sw2+="can't find..."
        elif(param1=="0x69"):
            if (param2 == "0x00"):
                sw2 += "No information given"
            elif (param2 == "0x81"):
                sw2 += "Command incompatible with file structure"
            elif(param2=="0x82"):
                sw2+="Security status not satisfied"
            elif(param2=="0x83"):
                sw2+="Authentication method blocked"
            elif(param2=="0x84"):
                sw2+="Reference data not usable"
            elif (param2 == "0x85"):
                sw2 += "Conditions of use not satisfied"
            elif(param2=="0x86"):
                sw2+="Command not allowed (no current EF)"
            elif(param2=="0x87"):
                sw2+="Expected secure messaging data objects missing"
            elif(param2=="0x88"):
                sw2+="Incorrect secure messaging data objects"
            else:
                sw2+="can't find..."
        elif (param1 == "0x6A"):
            if (param2 == "0x00"):
                sw2 += "No information given"
            elif (param2 == "0x80"):
                sw2 += "Incorrect parameters in the command data field"
            elif (param2 == "0x81"):
                sw2 += "Function not supported"
            elif (param2 == "0x82"):
                sw2 += "File of application not found"
            elif (param2 == "0x83"):
                sw2 += "Record not found"
            elif (param2 == "0x84"):
                sw2 += "Not enough memory space in the file"
            elif (param2 == "0x85"):
                sw2 += "Nc inconsistent with TLV structure"
            elif (param2 == "0x86"):
                sw2 += "Incorrect parameters P1-P2"
            elif (param2 == "0x87"):
                sw2 += "Nc inconsistent with parameters P1-P2"
            elif (param2 == "0x88"):
                sw2 += "Referenced data or reference data not found"
            elif (param2 == "0x89"):
                sw2 += "File already exists"
            elif (param2 == "0x8A"):
                sw2 += "DF name already exists"
            else:
                sw2+="can't find..."
        else:
            sw2 += "See SPEC"

        res+=sw2
        return res

    def msg2hex(self,message):
        begin = message.find('[')+1
        end = message.find(']')
        if(begin==-1 or end==-1):
            return []
        message = message[begin:end]
        msgs = message.split(',')
        res = []
        for msg in msgs:
            tmp = "0x"+"{:02x}".format((int(msg))).upper()
            res.append(tmp)

        return res




