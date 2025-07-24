from flask import json
from hfc.fabric import Client
from hfc.fabric_ca import ca_service
from hfc.util import utils
import asyncio

def __init__(self):
    self.client = None
    self.admin = None
    self.setup_fabric_client()

def setup_fabric_client(self):
    try:
        # Initialize Fabric client with network profile
        self.client = Client(net_profile="connection-profile.json")
        
        # Get admin user (you'll need to enroll this first)
        self.admin = self.client.get_user('Org1MSP', 'Admin')
        
    except Exception as e:
        print(f"Error setting up Fabric client: {e}")
        self.client = None

async def invoke_chaincode_async(self, function_name, args):
    """Invoke chaincode function asynchronously"""
    try:
        if not self.client or not self.admin:
            return {"error": "Fabric client not initialized"}
        
        # Create transaction context
        response = await self.client.chaincode_invoke(
            requestor=self.admin,
            channel_name='mychannel',
            peers=['peer0.org1.example.com'],
            args=args,
            cc_name='activitylog',
            fcn=function_name,
        )
        
        return {"success": True, "tx_id": response}
        
    except Exception as e:
        return {"error": str(e)}

def invoke_chaincode(self, function_name, args):
    """Synchronous wrapper for chaincode invoke"""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(self.invoke_chaincode_async(function_name, args))
    finally:
        loop.close()

async def query_chaincode_async(self, function_name, args):
    """Query chaincode function asynchronously"""
    try:
        if not self.client or not self.admin:
            return {"error": "Fabric client not initialized"}
        
        # Create query request
        response = await self.client.chaincode_query(
            requestor=self.admin,
            channel_name='mychannel',
            peers=['peer0.org1.example.com'],
            args=args,
            cc_name='activitylog',
            fcn=function_name,
        )
        
        # Parse response
        if response:
            return json.loads(response)
        else:
            return {"error": "No response from peers"}
            
    except Exception as e:
        return {"error": str(e)}

def query_chaincode(self, function_name, args):
    """Synchronous wrapper for chaincode query"""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(self.query_chaincode_async(function_name, args))
    finally:
        loop.close()