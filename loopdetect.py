#!/usr/bin/env python
# vim: set fileencoding=utf8 :
#

import sys
import time
import random
import socket
import pcapy
import dpkt
import dnet

def packetBody(length):
    """Генерирует случайное тело пакета"""
    rez = []
    for x in range(0,length):
        rez.append(random.choice('0123456789abcdef') + random.choice('0123456789abcdef'))
    return rez

class loopDetector:
    """Класс определяет наличие петли в сети"""
    packetCount = 0
    loopCount = 0
    # Время ожидания, секунд
    timeout = 1

    def __init__(self,iface):
        self.iface = iface
        self.pcaper = pcapy.open_live(iface,100,1,500)
        self.Mac = '00:19:5b:'+':'.join(packetBody(3))
        self.pcaper.setfilter('ether dst cf:00:00:00:00:00 and ether src %s' % self.Mac)

    def Capture(self,hdr,data):
        """Проверка если полученный пакет
        соответствует отправленному ранее"""
        if data == str(self.sPkt):
            self.packetReceived += 1

    def Process(self):
        while 1:
            try:
                # данные
                pktData = '00000001' + ''.join(packetBody(42))
                # генерируем ethernet фрейм
                self.sPkt = dpkt.ethernet.Ethernet(dst="cf0000000000".decode('hex'),
                                              src=''.join(self.Mac.split(':')).decode('hex'),
                                              type=36864,data=pktData.decode('hex'))
                # расчет времени ожидания
                endTime = time.time() + self.timeout
                print "Send packet to %s" % self.iface
                # количество отправленных пакетов
                self.packetCount += 1
                # отправка сгенерированного фрейма
                hw = dnet.eth(self.iface)
                hw.send(str(self.sPkt))
                # количество полученных пакетов
                self.packetReceived = 0
                # пока не вышло время ожидания
                while time.time() < endTime:
                    try:
                        # пробуем получить пакет
                        # и проверяем на соответствие ранее отправленному
                        self.pcaper.dispatch(-1,self.Capture)
                    except socket.timeout:
                        pass
                # Если было получено более одного пакета
                if self.packetReceived > 1:
                    # Увеличиваем счетчик и информируем об этом
                    self.loopCount += 1
                    print "Loop Detected. Duplication found %s" % self.packetReceived
            except KeyboardInterrupt:
                break
        print "Packets sent: ", self.packetCount , "Loops discovered : " , self.loopCount

def main():
    # получаем список устройств
    dev_list = {}
    n = 0
    iface = ''
    for x in pcapy.findalldevs():
        dev_list[n] = x
        n += 1
    # берем первое из списка
    try:
        iface = dev_list[0]
    except KeyError:
        print "No device found"
        exit(1)
    if len(sys.argv) == 2:
        try:
            if sys.argv[1] in  ['list','ls','all']:
                for x in dev_list:
                    print 'Index:', x, 'Device name:' ,dev_list[x]
                return 0
            else:
                iface = dev_list[int(sys.argv[1])]
        except KeyError:
            print "Invalid device id, trying use first"
            iface = dev_list[0]
    # запускаем на полученном устройстве детектор
    ld = loopDetector(iface)
    ld.Process()

if __name__ == "__main__":
    main()
