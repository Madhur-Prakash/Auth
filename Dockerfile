FROM ubuntu

RUN apt-get update && apt-get install -y curl

RUN sudo apt-get install libssl-dev openssl make gcc
RUN cd /opt
RUN wget https://www.python.org/ftp/python/3.10.11/Python-3.10.11.tgz
RUN tar xzvf Python-3.10.11.tgz
RUN cd Python-3.10.11
RUN ./configure 
RUN make
RUN make install
RUN sudo apt-get install python3-pip==23.0.1
RUN sudo apt install python3-venv
RUN python3 -m venv auth
RUN source auth/bin/activate

COPY .env .env
COPY authentication authentication 
COPY app app
COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt
RUN  uvicorn app:app
