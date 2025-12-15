# \[misc] Cloudy Days
> Expected Difficulty: 3
> Final Points: ???
> Solves: ??/?? (CUHK), ??/?? (Secondary), ??/?? (Invited Teams)
> 
> Alice: Cloudy days :(( Feels like it will rain soon :((
> 
> Malary: I know where you are hehehe :))
> 
> Flag format: `cuhk25ctf{<latitude>_<longitude>}`. The values should round to nearest 4 decimal places.

For challenges finding exact locations in the photo, there are no specific solving paths. However, I will list the important hints given in the photo which gives out the exact location.

## Hint 1: Bus 99
By dumping the photo to Google image search and focus the search specifically on the bus itself, you can see it is a bus run by company TransLink, a transportation authority running in Metro Vancouver. For now, you can focus on searching within Metro Vancouver instead of other places.

## Hint 2: Trafic Lights
If you know then you will know that those traffic lights are from Canada. This reinforces our claim in hint 1.

## Hint 3: Street Name Signs
There is a street sign which indicates the street name. However, it is a little bit blurry. However, by trying to brute force the street name and with some image enhancing techniques (like sharpening the image), you will be able to come up with "Alma St", which is a street in Vancouver. 

## Hint 4: Learn How To Read Street Name Signs
From [here](https://www.reddit.com/r/vancouver/comments/109lam8/comment/j3zuel8/?utm_source=share&utm_medium=web3x&utm_name=web3xcss&utm_term=1&utm_content=share_button), the street name signs are placed such that the drivers know which street they are crossing, instead of which street they are on. This provides an important hint that the photographer is on Alma Street.

## Combining Information
Since the photographer is on Alma Street, the bus is also actually on Alma Street, coincidentally. By checking the [official route of the bus line](https://www.translink.ca/schedules-and-maps/route/99/direction/1/map), there is only a short segment that the bus is on Alma Street. For now, we can just go to [Google Earth](https://earth.google.com/) and search around that segment.