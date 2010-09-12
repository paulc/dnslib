
from map import Map

TYPE =   Map({ 1:'A', 2:'NS', 3:'MD', 4:'MF', 5:'CNAME', 6:'SOA', 7:'MB', 
               8:'MG', 9:'MR', 10:'NULL', 11:'WKS', 12:'PTR', 13:'HINFO',
               14:'MINFO', 15:'MX', 16:'TXT',252:'AXFR',253:'MAILB',
               254:'MAILA',255:'*'})
CLASS =  Map({ 1:'IN', 2:'CS', 3:'CH', 4:'Hesiod', 255:'*'})
QR =     Map({ 0:'QUERY', 1:'RESPONSE' })
RCODE =  Map({ 0:'None', 1:'Format Error', 2:'Server failure', 
               3:'Name Error', 4:'Not Implemented', 5:'Refused' })
OPCODE = Map({ 0:'QUERY', 1:'IQUERY', 2:'STATUS' })


