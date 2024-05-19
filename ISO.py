class ISO_parser():
    def __init__(self):
        self.INS = {
            '44':'Activate File',
            'E2':'Append Record',
            '24':'Change Reference Data',
            'E0':'Create File',
            '04':'Deactivate File',
            'E4':'Delete File',
            '26':'Disable Verification Requirement',
            '28': 'Enable Verification Requirement',
            'C2':'Envelope',
            'C3':'Envelope',
            '0E':'Erase Binary',
            '0F': 'Erase Binary',
            '0C': 'Erase Record',
            '82': 'External Authenticate',
            '86': 'General Authenticate',
            '87': 'General Authenticate',
            '46': 'Generate Asymmetric Key Pair',
            '84': 'Get Challenge',
            'CA': 'Get Data',
            'CB': 'Get Data',
            'C0':'Get Response',
            '88':'Internal Authenticate',
            '70': 'Manage Channel',
            '22': 'Manage Security Environment',
            '10': 'Perform SCQL Operation',
            '2A': 'Perform Security Operation',
            '12': 'Perform Transaction Operation',
            '14': 'Perform User Operation',
            'DA':'Put Data',
            'DB': 'Put Data',
            'B0': 'Read Binary',
            'B1': 'Read Binary',
            'B2': 'Read Record',
            'B3': 'Read Record',
            '2C': 'Reset Retry Counter',
            'A0': 'Search Binary',
            'A1': 'Search Binary',
            'A2': 'Search Record',
            'A4': 'Select',
            'FE': 'Terminate Card Usage',
            'E6': 'Terminate DF',
            'E8': 'Terminate EF',
            'D6': 'Update Binary',
            'D7': 'Update Binary',
            'DC': 'Update Record',
            'DD': 'Update Record',
            '20': 'Verify',
            '21': 'Verify',
            'D0': 'Write Binary',
            'D1': 'Write Binary',
            'D2': 'Write Record'
        }