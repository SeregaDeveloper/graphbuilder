# !/bin/sh

echo "Установка необходимых компонентов...";
sleep 1;
sudo apt-get install python3-pip;
pip3 install pandas;
pip3 install networkx;
pip3 install matplotlib;
sudo apt-get install python-tk;
echo "Установка завершена!";
