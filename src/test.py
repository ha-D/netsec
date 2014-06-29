import sys, os, inspect

if __name__ == "__main__":
    
    # Add project directory to sys path
    cmd_folder = os.path.realpath(os.path.abspath(os.path.split(inspect.getfile( inspect.currentframe() ))[0]))
    if cmd_folder not in sys.path:
        sys.path.insert(0, cmd_folder)

    from tests import rsa_test