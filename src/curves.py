"""User-chosen diminishing returns; raw coverage is reported separately."""
def technique_score(count, saturation=30):
 if saturation<=0 or count<0:raise ValueError('Nonnegative count and positive saturation required')
 x=min(float(count)/saturation,1.0)
 return 1-(1-x)**2
