#!/bin/bash

gunicorn -w 4 server.api:app -b 0.0.0.0:5000