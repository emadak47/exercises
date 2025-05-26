## Problem Statement
In this exercise, we want to use our new knowledge to implement a broadcast chat application. We have a chat server that the clients connect to and publish their messages. The client reads user messages from the standard input, and sends them to the server. The chat server broadcasts each message that it receives to all the clients.


__Tasks__
1. Implement the handle_connection function in src/bin/server.rs.
    
    Hint: Use tokio::select! for concurrently performing two tasks in a continuous loop. 

    (a) One task receives messages from the client and broadcasts them.

    (b) The other sends messages received by the server to the client.

2. Complete the main function in src/bin/client.rs.
    
    Hint: As before, use tokio::select! in a continuous loop for concurrently performing two tasks:

    (a) reading user messages from standard input and sending them to the server, and 

    (b) receiving messages from the server, and displaying them for the user.
3. Optional: Once you are done, change the code to broadcast messages to all clients, but the sender of the message.

---

*\*Note: [https://google.github.io/comprehensive-rust/concurrency/async-exercises/chat-app.html]* 
