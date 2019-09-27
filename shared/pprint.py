from shared import colors

def state(current_state):
    print(colors.OKGREEN + '[*]\t' + current_state + colors.ENDC)

def information(info):
    print(colors.OKBLUE + '...\t' + info + colors.ENDC)

def error(error):
    print(colors.FAIL + '[!]\t' + error + colors.ENDC)




