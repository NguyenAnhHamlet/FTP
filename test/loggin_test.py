#!/usr/bin/python3

# Testing logging from client to server

"""
    1.  Both side check if both has RSA host-key algorithm

        a. Server does not have RSA -> Terminate
        b. Client does not have RSA -> Terminate 
        c. Both have -> Proceed to next step


    2.  Client connect to server with predetermined user name and password
        
        a.  User name is correct but password is not -> Reject
        b.  User name is incorrect but password correct -> Reject
        c.  User name and password both are not correct -> Reject
        d.  User name and password are correct -> Accept
    
    3. IP test 
        a. Correct IP address format -> Accept
        b. Incorrect IP address format -> Reject 

    4. TMOUT test
        a.  Could not proceed to next step for some reason (IP format is correct 
                                                            but IP address does not exist)
            -> Wait for 30 seconds and terminate process in client side
    
"""