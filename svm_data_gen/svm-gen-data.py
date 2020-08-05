import numpy
import time

# This data structure encodes the data for the model instead of using 
# arbitrary protocol numbers. This should probably be imported from the root directory somehow
protocolIndicators = {
    '6': 0,
    '17': 1,
    '1': 2,
}

# variable to change time frame of parameters
second = 3

def processData():
    """
    input: no parameters, but expects a csv in the same directory with columns:
    time, source IP, destination IP, protocol, ttl

    output: a csv in the same directory named processed-data.csv with the following columns:
    protocol, total # of packets in last second, 
    total # of unique source IP addresses in last second, 
    total # of packets to destination IP address in last second,
    and normal / bad class
    """

    print 'processing data....'
    
    # import the all the raw data as strings into a numpy array
    data = numpy.loadtxt(open('test.csv', 'rb'), delimiter=',', dtype='str')

    # ensure packets are sorted by time
    sortedIndices = numpy.argsort(data[:, 0])
    data = data[sortedIndices]

    for i in xrange(len(data)):
        # convert protocol to encoded value
        data[i, 3] = protocolIndicators[data[i, 3]]

    # create new array that will be used to generate processed-data.csv
    processedData = numpy.zeros((len(data), 5))

    # copy over protocol
    processedData[:, 0] = data[:, 3]

    # assign normal / bad class based on value encoded into packet's TTL
    # 1 = bad, 0 = normal
    for i in range(len(data)):
        processedData[i, 4] = 1 if int(data[i, 4]) < 50 else 0

    # calculate total # of packets in last second for each packet
    # initialize pointers and fill out first row
    lowPointer = 0
    processedData[0, 1] = 0
    for highPointer in xrange(1, len(data)):
        while lowPointer < highPointer and float(data[highPointer, 0]) - float(data[lowPointer, 0]) > second:
            lowPointer += 1

        # for this next line, lowPointer will always point to a packet
        # that is within one second of the currently pointed to packet
        # by highPointer. The difference is the total number of packets 
        # in the last second + one for the current packet
        processedData[highPointer, 1] = 1 + (highPointer - lowPointer)



    # calculate total # of unique source IPs in last second for each packet
    uniqueIPsInLastSecond = {} # a counter for # of unique IPs - when an IP's count reaches zero it's removed
    lowPointer = 0

    # add first packet's IP to counter
    uniqueIPsInLastSecond[data[lowPointer, 1]] = 1
    
    for highPointer in xrange(1, len(data)):
        newIP = data[highPointer, 1]

        if newIP in uniqueIPsInLastSecond:
            uniqueIPsInLastSecond[newIP] += 1
        else:
            uniqueIPsInLastSecond[newIP] = 1

        # remove any IPs from uniqueIPsInLastSecond if they're more than a second old and
        # their count reaches 0
        while lowPointer < highPointer and float(data[highPointer, 0]) - float(data[lowPointer, 0]) > second:
            IPtoRemove = data[lowPointer, 1]
            uniqueIPsInLastSecond[IPtoRemove] -= 1

            if uniqueIPsInLastSecond[IPtoRemove] < 1:
                del uniqueIPsInLastSecond[IPtoRemove]
            lowPointer += 1 
        
        processedData[highPointer, 2] = len(uniqueIPsInLastSecond)


    
    # calculate total # of times destination ip has received a packet in last second
    # initialize pointers and fill out first row
    destinationIPHitCountInLastSecond = {} # a counter for # of unique IPs - when an IP's count reaches zero it's removed
    lowPointer = 0
    
    # add first packet's IP to counter
    destinationIPHitCountInLastSecond[data[lowPointer, 2]] = 1

    for highPointer in xrange(1, len(data)):
        newIP = data[highPointer, 2]
        if newIP in destinationIPHitCountInLastSecond:
            destinationIPHitCountInLastSecond[newIP] += 1
        else:
            destinationIPHitCountInLastSecond[newIP] = 1

        # remove any IPs from destinationIPHitCountInLastSecond if they're more than a second old and
        # their count reaches 0
        while lowPointer < highPointer and float(data[highPointer, 0]) - float(data[lowPointer, 0]) > second:
            IPtoRemove = data[lowPointer, 2]
            destinationIPHitCountInLastSecond[IPtoRemove] -= 1

            if destinationIPHitCountInLastSecond[IPtoRemove] < 1:
                del destinationIPHitCountInLastSecond[IPtoRemove]
            lowPointer += 1 
        processedData[highPointer, 3] = len(destinationIPHitCountInLastSecond.keys())
    processedData = processedData.astype(int) # convert all floats to int
    numpy.savetxt('trainData.csv', processedData, delimiter=',', fmt='%d')
    print 'processed data successfully'
    
if __name__ == '__main__':
    processData()
