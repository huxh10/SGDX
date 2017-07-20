
class Route:
    def __init__(self):
        self.id=-1
        self.prefix=""
        self.neighbor=""
        self.next_hop=""
        self.as_path=[]
        self.communities=[]
        self.type=""
    def aspath_length(as_path):
        return len(as_path)
    def get_advertised_as(as_path):
        return as_path[0]
    def get_id(self):
        return self.id
    def __str__(self):
        return "route:(id:" + str(self.id) + ", prefix:" + str(self.prefix) + ", "+ ", neighbor:" + str(self.neighbor) + ", " + ", next_hop:" + str(self.next_hop) + ", " + ", as_path:" + str(self.as_path) + ", " + ", communities:" + str(self.communities) + ", type: "+ self.type +")"
    def __repr__(self):
        return self.__str__()

''' simplified BGP decision process '''
def compare_routes(route1,route2):
    if len(route1.as_path) != len(route2.as_path):
        return len(route1.as_path) - len(route2.as_path)
    else:
        if(route1.next_hop < route2.next_hop):
            return -1
        else:
            return 1