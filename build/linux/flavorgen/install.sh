#!/bin/bash

COMPONENT_NAME=flavorgen

SERVICE_USERNAME=flavorgen

if [[ $EUID -ne 0 ]]; then 
    echo "This installer must be run as root"
    exit 1
fi

echo "Setting up flavorgen Linux User..."
# useradd -M -> this user has no home directory
id -u $SERVICE_USERNAME 2> /dev/null || useradd -M --system --shell /sbin/nologin $SERVICE_USERNAME

echo "Installing flavorgen..."

PRODUCT_HOME=/opt/$COMPONENT_NAME
BIN_PATH=$PRODUCT_HOME/bin
CONFIG_PATH=/etc/$COMPONENT_NAME/
SCHEMA_PATH=$CONFIG_PATH/schema

for directory in $BIN_PATH $CONFIG_PATH $SCHEMA_PATH; do
  # mkdir -p will return 0 if directory exists or is a symlink to an existing directory or directory and parents can be created
  mkdir -p $directory
  if [ $? -ne 0 ]; then
    echo_failure "Cannot create directory: $directory"
    exit 1
  fi
  chown -R $SERVICE_USERNAME:$SERVICE_USERNAME $directory
  chmod 700 $directory
done

chown -R $SERVICE_USERNAME:$SERVICE_USERNAME $CONFIG_PATH
chmod -R 700 $CONFIG_PATH

cp $COMPONENT_NAME $BIN_PATH/ && chown $SERVICE_USERNAME:$SERVICE_USERNAME $BIN_PATH/*
chmod 700 $BIN_PATH/*
ln -sfT $BIN_PATH/$COMPONENT_NAME /usr/bin/$COMPONENT_NAME

# Copy Schema files
cp -r schema/ $CONFIG_PATH/ && chown $SERVICE_USERNAME:$SERVICE_USERNAME $SCHEMA_PATH/*

echo "Installation completed successfully!"
