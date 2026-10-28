class CowrieConfig:
  @staticmethod
  def get(section, option, fallback=None):
    if option == "hostname": return "ubuntu"
    return fallback
  
  @staticmethod
  def getboolean(section, option, fallback=False):
    return fallback

def getConfig():
  return CowrieConfig()