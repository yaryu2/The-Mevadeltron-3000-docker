import configparser
import json


def multiple_inputs(s):
    l = []
    temp_input = input(s)
    while True:
        if temp_input == '':
            break
        l.append(temp_input)
        temp_input = input()
    return l


def main():
    config = configparser.ConfigParser()
    name = input('Enter the name of the protocol:\r\n')

    count_request = input('Enter the amount of messages that are legitimate to receive per minute:\r\n')

    port = multiple_inputs('Enter the port that the protocol listen on:\r\n')

    white_list = multiple_inputs('Enter white list of commands that can be obtained:\r\n')

    first_response = multiple_inputs('Enter the message to send at the start of the connection (option):\r\n')

    config[name] = {}
    config[name]['Port'] = json.dumps(port)
    config[name]['Count Request'] = count_request
    config[name]['White List'] = json.dumps(white_list)
    config[name]['First Response'] = '\n'.join(first_response)

    print('Protocol name = ' + name)
    print('Port = ' + config[name]['Port'])
    print('Count Request = ' + config[name]['Count Request'])
    print('White List = ' + config[name]['White List'])
    print('First Response = ' + config[name]['First Response'])

    if input('Enter (y/n) if you agree to add these protocol: \n\r') == 'y' or 'Y':
        with open('config.ini', 'a') as configfile:
            config.write(configfile)


if __name__ == '__main__':
    main()