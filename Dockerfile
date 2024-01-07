FROM ubuntu:latest

RUN apt update 
RUN apt install nftables iproute2 vim python3 pip -y
RUN apt upgrade -y
RUN mkdir KeyboardKowboys
COPY . /KeyboardKowboys
WORKDIR /KeyboardKowboys
RUN pip install -r requirements.txt
ENTRYPOINT [ "python3", "nifty_firewall_tool.py" ]