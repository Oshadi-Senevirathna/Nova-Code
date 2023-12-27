import { Grid, Input, Typography, Paper } from '@material-ui/core';
import {useReactToPrint} from 'react-to-print';
import EntityDataTable from '../../../framework/components/tables/entity-data-table-report';
import React, { useEffect, useState, useRef } from 'react';
import logo from '../../../assets/login-logo.png'
import { makeStyles } from '@material-ui/core/styles';
import {TextField} from '@material-ui/core';
import {MenuItem} from '@material-ui/core';
import Card from '@material-ui/core/Card';
import CardContent from '@material-ui/core/CardContent';
import Box from '@material-ui/core/Box';
import Button from '@material-ui/core/Button';
import { ENTITY_NAME_DEVICE, ENTITY_NAME_DEVICE_ADAPTOR, ENTITY_NAME_CLOUD_PROVIDERS, ENTITY_NAME_DEVICE_CATEGORY, ENTITY_NAME_DEVICE_CONNECTION_METHOD } from '../../../framework/caching/entity-cache';
import serviceFactoryInstance from '../../../services/service-factory';
import { Radio, RadioGroup, FormControlLabel, FormControl, FormLabel } from '@material-ui/core';
import Checkbox from '@material-ui/core/Checkbox';
import ipFilter from '../../../framework/validations/ip-filter';
import configs from './inventory-config.json';

const useStyles = makeStyles((theme) => ({
  root: {
    flexGrow: 1,
    width: '96%',
    marginTop: "2%" ,
    marginLeft:'auto',
    marginRight:'auto'
  },
  progressBar: {
    marginTop: '20px',
    marginBottom: '20px',
    marginRight: '20px',
  },
  button: { marginRight: '20px' },
  heading: {
    fontSize: theme.typography.pxToRem(20),
    fontWeight: theme.typography.fontWeightBold,
    paddingBottom: 15,
  },
  subheading: {
    fontWeight: theme.typography.fontWeightBold,
    fontSize: theme.typography.pxToRem(18),
  },
  disable:{
    backgroundColor:"#f5f5f5"
  }
}));

const InventoryReportingPage = ({ module, cache }) => {
  const classes = useStyles();
  const [dropdownValues, setDropdownValues] = useState({});
  const [deviceType, setDeviceType] = useState('all')
  const [deviceStatus, setDeviceStatus] = useState('all')
  const [deviceCategory, setDeviceCategory]= useState('all')
  const [deviceAdaptor, setDeviceAdaptor] = useState('all')
  const [deviceConnectionMethod, setDeviceConnectionMethod] = useState('all')
  const [ip0, setIp0] = useState(0)
  const [ip1, setIp1] = useState(0)
  const [ip2, setIp2] = useState(0)
  const [ip3Start, setIp3Start] = useState(0)
  const [ip3End, setIp3End] = useState(0)
  const [useIPFilter, setUseIPFilter] = useState(false)
  const [instances, setInstances] = useState([])
  const [filterSuccess, setFilterSuccess] = useState(false)
  const [filterLabel, setFilterLabel] = useState([])
  const [reportName, setReportName] = useState('Inventory Report')
  const [cloudProviders, setCloudProviders] = useState()
  const myRef = useRef(null)

  useEffect(() => {   
    
    const dropdowns = {};

    var deviceStatusList = []
    deviceStatusList.push({
      value:"New",
      label:"New"
    })
    deviceStatusList.push({
      value:"Discovred",
      label:"Discovered"
    })
    deviceStatusList.push({
      value:"Last Discovered",
      label:"Last Discovered"
    })
    deviceStatusList.push({
      value:"Last Discovery Failed",
      label:"Last Discovery Failed"
    })
    deviceStatusList.push({
      value:"all",
      label:"All"
    })
    dropdowns["device_status"] = deviceStatusList

    var deviceTypeList = []
    deviceTypeList.push({
      value:"router",
      label:"Router"
    })
    deviceTypeList.push({
      value:"switch",
      label:"Switch"
    })
    deviceTypeList.push({
      value:"cloud",
      label:"Cloud"
    })
    deviceTypeList.push({
      value:"firewall",
      label:"Firewall"
    })
    deviceTypeList.push({
      value:"ap",
      label:"AP"
    })
    deviceTypeList.push({
      value:"loadbalancer",
      label:"Loadbalancer"
    })
    deviceTypeList.push({
      value:"all",
      label:"All"
    })
    dropdowns['device_type'] = deviceTypeList

    const cloudProvidersSub = serviceFactoryInstance.dataLoaderService.dataSub(ENTITY_NAME_CLOUD_PROVIDERS)
        .subscribe((data)=>{
        if (data) {
          let arrayTemp = []
          for(let i=0;i<data.length;i++){
            let temp = {}
            temp.instance_name = data[i].instance_name
            temp.display_name = data[i].display_name
            temp.definition = {}
            temp.definition.fields = data[i].parameters
            arrayTemp.push(temp)            
          }
            setCloudProviders(arrayTemp);
          }
        });
        
    const categorySub = serviceFactoryInstance.dataLoaderService.dataSub(`${ENTITY_NAME_DEVICE_CATEGORY}>${module}`)
      .subscribe((data)=>{
        if (data) {
          var deviceCategoryList = []
          for(let i=0;i<data.length;i++){
            const instance = data[i]
            if(deviceType && deviceType===instance.category || deviceType==='all'){
              deviceCategoryList.push({
                value: instance.UUID,
                label: instance.instance_name,
              });
            }
          }
          deviceCategoryList.push({
            value:"all",
            label:"All"
          })
          dropdowns['device_category'] = deviceCategoryList
        }
      });
    
    const adaptorSub = serviceFactoryInstance.dataLoaderService.dataSub(ENTITY_NAME_DEVICE_ADAPTOR)
      .subscribe((data)=>{
        if (data) {
          const deviceAdaptorList = data.map((instance) => {
              return {
                value: instance.UUID,
                label: instance.instance_name,
              };
          });
          deviceAdaptorList.push({
            value:"all",
            label:"All"
          })
          dropdowns['device_adaptor'] = deviceAdaptorList
        }
      });

    const connectionMethodSub = serviceFactoryInstance.dataLoaderService.dataSub(ENTITY_NAME_DEVICE_CONNECTION_METHOD)
      .subscribe((data)=>{
        if (data) {
          const deviceConnectionMethodList = data.map((instance) => {
              return {
                value: instance.UUID,
                label: instance.instance_name,
              };
          });
          deviceConnectionMethodList.push({
            value:"all",
            label:"All"
          })
          dropdowns['device_connection_method'] = deviceConnectionMethodList
        }
      });
      
      setDropdownValues(dropdowns);
    
    return () => {
      cloudProvidersSub.unsubscribe();
      adaptorSub.unsubscribe();
      categorySub.unsubscribe();
      connectionMethodSub.unsubscribe();
    };
  }, [deviceType]);

  const onClearFilter = (event) =>{
    setDeviceType('all')
    setDeviceStatus('all')
    setDeviceCategory('all')
    setDeviceAdaptor('all')
    setDeviceConnectionMethod('all')
    setIp0(0)
    setIp1(0)
    setIp2(0)
    setIp3Start(0)
    setIp3End(0)
  }

  const onDownloadPDF = useReactToPrint({
    content : () => myRef.current,
  })
  
  const onRunFilter = (event) =>{

    var temp = []
      
    var fields = []
    var values = []
    var direction = []

    if(deviceType!=='all'){
      fields.push(`"category"`)
      values.push(`"${deviceType}"`)
      direction.push(`"0"`)
      for(let i=0; i<dropdownValues['device_type'].length;i++){
          if(dropdownValues['device_type'][i].value===deviceType){
            temp.push(`Device type : ${dropdownValues['device_type'][i].label}`)
          }
        }
    }else{
      temp.push(`Device type : Any`)
    } 

    if(deviceStatus!=='all'){
      fields.push(`"device_status"`)
      values.push(`"${deviceStatus}"`)
      direction.push(`"0"`)
      for(let i=0; i<dropdownValues['device_status'].length;i++){
        if(dropdownValues['device_status'][i].value===deviceStatus){
          temp.push(`Device status : ${dropdownValues['device_status'][i].label}`)
        }
      }
    }else{
      temp.push(`Device status : Any`)
    } 

    if(deviceCategory!=='all'){
      fields.push(`"device_category"`)
      values.push(`"${deviceCategory}"`)
      direction.push(`"0"`)
      for(let i=0; i<dropdownValues['device_category'].length;i++){
        if(dropdownValues['device_category'][i].value===deviceCategory){
          temp.push(`Device category : ${dropdownValues['device_category'][i].label}`)
        }
      }
    }else{
      temp.push(`Device category: Any`)
    } 

    if(deviceAdaptor!=='all'){
      fields.push(`"adaptor"`)
      values.push(`"${deviceAdaptor}"`)
      direction.push(`"0"`)
      for(let i=0; i<dropdownValues['adaptor'].length;i++){
        if(dropdownValues['adaptor'][i].value===deviceAdaptor){
          temp.push(`Device adaptor : ${dropdownValues['adaptor'][i].label}`)
        }
      }
    }else{
      temp.push(`Device adaptor : Any`)
    } 

    if(deviceConnectionMethod!=='all'){
      fields.push(`"connection_method"`)
      values.push(`"${deviceConnectionMethod}"`)
      direction.push(`"0"`)
      for(let i=0; i<dropdownValues['connection_method'].length;i++){
        if(dropdownValues['connection_method'][i].value===deviceConnectionMethod){
          temp.push(`Device connection method : ${dropdownValues['connection_method'][i].label}`)
        }
      }
    }else{
      temp.push(`Device connection method : Any`)
    }
    
    setFilterLabel(temp)
    
    serviceFactoryInstance.reportingService.reportingFilter(ENTITY_NAME_DEVICE, `[${fields}]`, `[${values}]`, `[${direction}]`, 'created_at', 1, module)
        .then((data) => {
          if(data.status){
            setFilterSuccess(true)
            if(useIPFilter){
              var ipPre = ip0.toString() + '.' + ip1.toString() + '.' + ip2.toString()
              const filtered = ipFilter(data.instances, ipPre, ip3Start, ip3End)
              setInstances(filtered)
              console.log(filtered)
            }else{
              setInstances(data.instances)
              console.log(data.instances)
            }
          }else{
            setFilterSuccess(false)
            setInstances([])
          }
        });
    
  }
  
  const onChangeFilterValue = (stateSet, event) =>{
    stateSet((event.target.value).toString())
  }
  
  const onChangeIPValue = (stateSet, event, start3, end3) =>{
    var temp = parseInt(event.target.value)
    if(!isNaN(temp)){
      if(start3 && ip3End<temp){
        if(temp<=255){
          setIp3End(temp)
        }
        else{
          setIp3End(255)
        }
      }
      if(end3 && temp<ip3Start){
        temp = ip3Start
      }

      if(temp<=255){
        stateSet(temp)
      }
      else{
        stateSet(255)
      }
    }
    else{
      stateSet(0)
    }
  }
  
  return (
      <div className={classes.root}>
        
      <Card>
      <CardContent>
        <Typography className={classes.heading}>Filter Parameters</Typography>
        <div  style={{width:"45%", display:'inline-flex', padding:'10px' }}>
          <div  style={{width:"50%"}}>
          <Typography>
            Device Status
          </Typography>
          </div>
          <div style={{width:'50%', float:'right'}}>
          {(dropdownValues && dropdownValues['device_status']) ? 
            <>
            <TextField
              value = {deviceStatus || ''}
              style={{width:"100%"}}
              key={'device_status'}
              select
              name={'device_status'}
              onChange={(event)=>onChangeFilterValue(setDeviceStatus,event)}
              fullWidth
            >
              {dropdownValues && dropdownValues['device_status'] &&
              dropdownValues['device_status'].map((option) => (
                <MenuItem key={option.value} value={option.value}>
                {option.label}
                </MenuItem>
              ))}
            </TextField>
            </>
          :
            <>
            <TextField
            style={{width:"100%"}}
            fullWidth
            />
            </>
          }
          </div>
        </div>
        <div  style={{width:"45%", display:'inline-flex', float:'right', padding:'10px' }}>
          <div  style={{width:"50%"}}>
          <Typography>
            Device Type
          </Typography>
          </div>
          <div style={{width:'50%', float:'right'}}>
          {(dropdownValues && dropdownValues['device_type']) ? 
            <>
            <TextField
              value = {deviceType || ''}
              style={{width:"100%"}}
              key={'device_type'}
              select
              name={'device_type'}
              onChange={(event)=>onChangeFilterValue(setDeviceType,event)}
              fullWidth
            >
              {dropdownValues && dropdownValues['device_type'] &&
              dropdownValues['device_type'].map((option) => (
                <MenuItem key={option.value} value={option.value}>
                {option.label}
                </MenuItem>
              ))}
            </TextField>
            </>
          :
            <>
            <TextField
            style={{width:"100%"}}
            fullWidth
            />
            </>
          }
          </div>
        </div>
        <div  style={{width:"45%", display:'inline-flex', padding:'10px' }}>
          <div  style={{width:"50%"}}>
          <Typography>
            Device Category
          </Typography>
          </div>
          <div style={{width:'50%', float:'right'}}>
          {(dropdownValues && dropdownValues['device_category']) ? 
            <>
            <TextField
              value = {deviceCategory || ''}
              style={{width:"100%"}}
              key={'device_category'}
              select
              name={'device_category'}
              onChange={(event)=>onChangeFilterValue(setDeviceCategory,event)}
              fullWidth
            >
              {dropdownValues && dropdownValues['device_category'] &&
              dropdownValues['device_category'].map((option) => (
                <MenuItem key={option.value} value={option.value}>
                {option.label}
                </MenuItem>
              ))}
            </TextField>
            </>
          :
            <>
            <TextField
            style={{width:"100%"}}
            fullWidth
            />
            </>
          }
          </div>
        </div>
        <div  style={{width:"45%", display:'inline-flex', float:'right', padding:'10px' }}>
          <div  style={{width:"50%"}}>
          <Typography>
            Device Adaptor
          </Typography>
          </div>
          <div style={{width:'50%', float:'right'}}>
          {(dropdownValues && dropdownValues['device_adaptor']) ? 
            <>
            <TextField
              value = {deviceAdaptor || ''}
              style={{width:"100%"}}
              key={'device_adaptor'}
              select
              name={'device_adaptor'}
              onChange={(event)=>onChangeFilterValue(setDeviceAdaptor,event)}
              fullWidth
            >
              {dropdownValues && dropdownValues['device_adaptor'] &&
              dropdownValues['device_adaptor'].map((option) => (
                <MenuItem key={option.value} value={option.value}>
                {option.label}
                </MenuItem>
              ))}
            </TextField>
            </>
          :
            <>
            <TextField
            style={{width:"100%"}}
            fullWidth
            />
            </>
          }
          </div>
        </div>
        <div  style={{width:"45%", display:'inline-flex', padding:'10px' }}>
          <div  style={{width:"50%"}}>
          <Typography>
            Connection Method
          </Typography>
          </div>
          <div style={{width:'50%', float:'right'}}>
          {(dropdownValues && dropdownValues['device_connection_method']) ? 
            <>
            <TextField
              value = {deviceConnectionMethod || ''}
              style={{width:"100%"}}
              key={'device_connection_method'}
              select
              name={'device_connection_method'}
              onChange={(event)=>onChangeFilterValue(setDeviceConnectionMethod,event)}
              fullWidth
            >
              {dropdownValues && dropdownValues['device_connection_method'] &&
              dropdownValues['device_connection_method'].map((option) => (
                <MenuItem key={option.value} value={option.value}>
                {option.label}
                </MenuItem>
              ))}
            </TextField>
            </>
          :
            <>
            <TextField
            style={{width:"100%"}}
            fullWidth
            />
            </>
          }
          </div>
        </div>
        <br/>
        <Card>
        <CardContent  className={!useIPFilter && classes.disable}>
          <FormControlLabel
            control={
              <Checkbox
                checked={useIPFilter}
                onChange={(event) => {
                  setUseIPFilter(!useIPFilter)
                }}
                name="useIPFilter"
              />
            }
            label={<Typography className={classes.subheading}>Use IP range filter</Typography>}
          />
          <br/>
          <div style={{width:"100%", display:'inline-flex', padding:'10px' }}> 
          <div style={{width:"21%"}}> 
          <Typography>
            IP Address Range
          </Typography>
          </div>
          <div style={{width:'50%', float:'left', paddingBottom:"10px"}}>
            <>
              <TextField
              style={{width:"10%"}}
              variant = 'outlined'
              fullWidth
              value={ip0}
              disabled={!useIPFilter}
              onChange={(event)=>onChangeIPValue(setIp0, event)}
              />
              <TextField
              style={{width:"10%"}}
              variant = 'outlined'
              fullWidth
              value={ip1}
              disabled={!useIPFilter}
              onChange={(event)=>onChangeIPValue(setIp1, event)}
              />
              <TextField
              style={{width:"10%"}}
              variant = 'outlined'
              fullWidth
              value={ip2}
              disabled={!useIPFilter}
              onChange={(event)=>onChangeIPValue(setIp2, event)}
              />
              <TextField
              style={{width:"10%"}}
              variant = 'outlined'
              fullWidth
              value={ip3Start}
              disabled={!useIPFilter}
              onChange={(event)=>onChangeIPValue(setIp3Start, event, 1, 0)}
              />
              <div style={{width:"10%", display:'inline-flex'}}>
              <p style={{padding:'auto', margin:'auto', paddingTop:'10px'}}>
                -  
              </p>
              </div>       
              <TextField
              style={{width:"10%"}}
              variant = 'outlined'
              fullWidth
              disabled={true}
              value={ip0}
              />
              <TextField
              style={{width:"10%"}}
              variant = 'outlined'
              fullWidth
              disabled={true}
              value={ip1}
              />
              <TextField
              style={{width:"10%"}}
              variant = 'outlined'
              fullWidth
              disabled={true}
              value={ip2}
              />
              <TextField
              style={{width:"10%"}}
              variant = 'outlined'
              fullWidth
              value={ip3End}
              disabled={!useIPFilter}
              onChange={(event)=>onChangeIPValue(setIp3End, event, 0, 1)}
              />
            </>
            </div>
          </div>
        </CardContent>
        </Card>
      </CardContent>
      </Card>
      <Box display="flex" alignItems="center" className={classes.progressBar}>
        <Button variant="contained" color="primary" className={classes.button} onClick={onRunFilter}>
          Run Filter
        </Button>
        <Button variant="contained" color="primary" className={classes.button} onClick={onClearFilter}>
          Clear Filter
        </Button>
        <Button variant="contained" color="primary" className={classes.button} onClick={onDownloadPDF}>
          Download PDF
        </Button>
      </Box>
      {filterSuccess && 
      <Grid item ref={myRef} display='flex'>
        <Paper variant="elevation" elevation={0} style={{padding:40, width:'1100px', maxWidth:'1100px', margin:'auto'}}>
          <Grid item> 
          <Grid container direction="row">
            <Grid item xs={8} align='left'> 
            <Grid container justifyContent="start" alignItems='flex-start' direction="column" >
              <Typography className={classes.heading}>{reportName}</Typography>
              {filterLabel && 
              <div>
                <Typography className={classes.subheading}>Filters used</Typography>
                {filterLabel &&
                filterLabel.map((label)=>{
                  return <Typography >{label}</Typography>
                })
              }
              <br/>
              </div>}
            </Grid>
            </Grid>
            <Grid item xs={4}> 
            <Grid container direction="column" justifyContent="center" alignItems="flex-end">
              <img src={logo}  align='right' alt="InSync Login Logo Not Found" max-height="131px" height="131px" width="186px" max-width="186px"/>
            </Grid>
            </Grid>
            <br/> 
            {configs.map((config)=>{
              return <>
              {config.category==='cloud' && (deviceType==='all' || deviceType==='cloud')?
              <>
              {cloudProviders.map((cloudConfig)=>{
              return <div style={{marginRight:'auto'}}>
                <Typography className={classes.subheading}>{config.name} : {cloudConfig.display_name}</Typography>
                <EntityDataTable 
                cache={cache} module={module} 
                data={instances.filter((device) => {
                  var match = false
                  if (device['category'] === config.category && device['cloud_provider'] === cloudConfig.instance_name){
                    match = true
                  }
                  return match
                })}
                def={cloudConfig.definition} 
                noSearch={true}
                selectAll={false}>
                </EntityDataTable>
                <br/>
              </div>
              })}
              </>
              :
              <>
              {(config.category===deviceType || deviceType === 'all') &&
              <div style={{marginRight:'auto'}}>
              <Typography className={classes.subheading}>{config.name}</Typography>
              <EntityDataTable 
              cache={cache} module={module} 
              data={instances.filter((device) => {
                var match = false
                if (device['category'] === config.category){
                  match = true
                }
                return match
              })}
              def={config.definition} 
              noSearch={true}
              selectAll={false}>
              </EntityDataTable>
              <br/>
              </div>
              }
              </>
              }
              </>
            })}
            </Grid>
            </Grid>
          </Paper>
      </Grid>
    }
      <br/>
      </div>
  );
};

export default InventoryReportingPage;
