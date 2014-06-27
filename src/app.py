import sys, os, inspect
import nodes.ca

nodeList = {
    'client': None,
    'ca': nodes.ca.CAServer,
    'authority': None,
    'collector': None
}

if __name__ == "__main__":
    
    # Add project directory to sys path
    cmd_folder = os.path.realpath(os.path.abspath(os.path.split(inspect.getfile( inspect.currentframe() ))[0]))
    if cmd_folder not in sys.path:
        sys.path.insert(0, cmd_folder)

    cmd_subfolder = os.path.realpath(os.path.abspath(os.path.join(os.path.split(inspect.getfile( inspect.currentframe() ))[0],"subfolder")))
    if cmd_subfolder not in sys.path:
        sys.path.insert(0, cmd_subfolder)


    def usage():
        print("Please enter one of the following network nodes to run:")
        for node in nodeList:
            print(" * " + node)
        exit(1)

    if len(sys.argv) < 2:
        usage()

    nodeName = sys.argv[1]
    if nodeName not in nodeList:
        print("No such network node '%s'" % nodeName)
        usage()

    # Remove node name from argv to prevent it being parsed later
    sys.argv.pop(1)

    node = nodeList[nodeName]()
    node.start()

