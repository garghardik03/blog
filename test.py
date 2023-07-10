import razorpay

client = razorpay.Client(auth=("rzp_test_3fT7czS7jEsTzs", "Ne27btY8oetWfz3rAy7pe6dB"))
result = client.keys.create({
    "name": "Live key 1",
    "key_type": "live"  
})
