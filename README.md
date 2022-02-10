# VW API Package
This is a simple python3 package can log into a VW ID and query several VW 
APIs.

Forked from original repo by [vr-hunter](https://github.com/vr-hunter/vwapi). Asynchronous implementation caused problems with AWS Lambda therefore replaced in this repo with synchronous requests.

It uses requests for synchronous http connections.

Currently, the functionality is limited to 
- Logging in to the VW ID
- Adding / removing vehicles to / from the VW ID
- Querying the "relations" and "lounge" APIs. The former returns 
information on vehicles associated with the VW ID, the latter returns the production 
status of newly purchased vehicles

## Example Usage

    import vwapi
    
    session = vwapi.VWSession("my_vw_id@gmail.com", "my_vw_id_password")
	session.log_in()
	cars = session.get_cars()
	print(cars)
