# pathend
We present a prototype implementation, which complements RPKI and allows to deploy path-end validation with today's routing infrastructure.
We envision this prototype as a first step, providing an immediate defense against path-manipulation attacks,
before path-end validation is integrated into RPKI. Our prototype is compatible with RPKI to simplify future migration. 

This project has two directories:
1. The agent directory holds the code for the path-end agent which deploys filtering rules at your BGP routers.
2. The db directory holds the code for the repository servers, you can run and deploy your own server.

The directories come with seperate READMEs that explain how to run each service.
