# Virtue Burp Power Tools

Virtue Burp Power Tools is a Burp Extension (Using Montoya API) produced by [Virtue Security](https://www.virtuesecurity.com) that we use in our penetration tests to support probing applications for vulnerabilities, providing custom session handling, and supporting extraction of information for documentation in Markdown format. The features include:

- Right-Click Context Menu:
  - Copy one or more requests and responses to support pasting the information as Markdown into notes or reports
    - Variety of copy modes ranging from copying the entire request and response to capturing just the URLs or headers
  - Select one or more requests and resend them, observing their result in the "logger" tab
    - This supports using session handling rules to manipulate requests at scale and observe the results
  - Select one or more requests and attempt standard and non-existent HTTP verbs for each URL and observe the results in the "logger" tab
  - Add or exclude the base URL of selected requests to the scope for the project
  - Send multiple requests to organizer (historically, Burp only lets you do one at a time)
  - Send multiple requests to repeater and automatically name the tabs based on the HTTP Verb and Path
  - Configure JWT handling logic plus provide a session handling "action" to watch for changes in tokens and automatically add them to new requests for various tools
  - Use one or more requests as a base to launch a wide variety of test cases against an end-point and observe the results in the "logger" tab

## Setup

### Building the Extension

Build this plugin by cloning the repository and then running:

- Linux: `gradlew shadowJar`
- Windows: `gradlew.bat shadowJar`

This command will create a jar file in the `build/libs` directory called `VirtueBurpPowerTools-x.y.z-all.jar` where `x.y.z` is the version number of the plugin.

### Adding the Extension to Burp Suite

1. Open Burp Suite
2. Click the "Extensions" tab
3. Click "Add"
4. For "Extension Type", choose "Java"
5. Click the "Select File" button, and choose the `VirtueBurpPowerTools-x.y.z-all.jar` from above

## Usage

### Session Handling Features

#### Using the plugin as a Session Handling Action

This mode of operation will watch for access tokens and apply them to any request covered by your session handling rule as described below

- In the session handling rules within Burp Suite's settings, Add a new rule, and add the action: "Invoke a Burp Extension". Choose "Access Token Helper"
- In the Session Access Token Helper's settings, check mark "Use Passively For All Requests?"`
- Configure your scope and tools you want it to apply to

#### Using the plugin with a Login Macro

This mode of operation tries to apply the access token to all new requests, and if the request fails you "check session is valid" rule, it uses a login macro you define, obtains the access token from that macro, and applies it to the request and re-issues it.

- Record a macro that logs into an application (this is a core feature of burp suite and is beyond the scope of this document)
- Verify the json returning has `"access_token":"access token here"` in the response (or a custom pattern you change in this plugin's settings)
- In the session handling rules within Burp Suite's settings, Add a new rule, and add the action: "Invoke a Burp Extension". Choose "Access Token Helper"
- Configure your scope and tools you want it to apply to
- Create a second session rule using the "check session is valid" rule
    - Select "Issue Current Request"
    - Configure the "inspect response to determine session validity" to identify responses indicating you are no longer logged into the application
    - Select "if session is invalid, perform the action below", "Run a macro", Choose the login macro you created above
    - Select "After running the macro, invoke a burp extension handler", and select "Access Token Helper" 