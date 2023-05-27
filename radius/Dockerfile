FROM ubuntu:latest

# Install FreeRADIUS
RUN apt update && apt install -y freeradius

# Stop FreeRADIUS
RUN service freeradius stop

ENTRYPOINT [ "/bin/sh", "-c", "service freeradius start && sh" ];