import json
from boto3 import client
ecr = client('ecr')

def get_image_parameters(image_uri):
    parameters = image_uri.split(':')
    repository_name = parameters[0].split('/')[1]
    image_tag = parameters[1]
    return repository_name, image_tag
    
def has_vulnerabilities(repository_name, image_tag):
    print('Checking image for vulnerabilities')
    findings = ecr.describe_image_scan_findings(
        repositoryName = repository_name,
        imageId = {
            'imageTag': image_tag
        }
    )['imageScanFindings']['findings']
    vulnerabilities = filter(lambda x : x['severity'] == 'CRITICAL', findings)
    return list(vulnerabilities)

def lambda_handler(event, context):
    body = json.loads(event['body'])
    pod = body['request']['object']
    containers = pod['spec']['containers']
    for container in containers: 
        image_uri = container['image']
        if 'amazonaws.com' in image_uri:
            repository_name, image_tag = get_image_parameters(image_uri)
            vulnerabilities = has_vulnerabilities(repository_name, image_tag)
            if vulnerabilities != None:
                message = "The pod contains the following critical CVEs: "
                for cve in vulnerabilities:
                    message += ''.join(cve['name']) + " "
                return {"response": {"allowed": False, "status": {"message": message}}}
            else:
                return {"response": {"allowed": True, "status": {"message": "pod accepted"}}}
        else:
            return {"response": {"allowed": True, "status": {"message": "pod accepted"}}}
