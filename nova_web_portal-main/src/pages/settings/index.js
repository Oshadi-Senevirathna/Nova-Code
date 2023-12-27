import {
    Accordion,
    AccordionActions,
    AccordionDetails,
    AccordionSummary,
    Button,
    Divider,
    Grid,
    Typography
} from '../../../node_modules/@mui/material/index';
import { CaretDownOutlined } from '@ant-design/icons';
import { makeStyles } from '../../../node_modules/@mui/styles/index';
import React, { useEffect, useReducer, useState } from 'react';
import { ENTITY_NAME_SETTINGS } from 'framework/caching/entity-cache';
import serviceFactoryInstance from 'framework/services/service-factory';
import PasswordInputSetting from './password-input-setting';
import SliderSetting from './slider-setting';
import TextInputSetting from './text-input-setting';
import ToggleSetting from './toggle-setting';
import config from './common-settings.json';
import CustomSnackbar from 'components/styledMUI/Snackbar';
import ArraySetting from './array-setting';

const useStyles = makeStyles((theme) => ({
    root: {
        flexGrow: 1,
        width: '96%',
        marginTop: '2%',
        marginLeft: 'auto',
        marginRight: 'auto'
    },
    heading: {
        fontSize: '1rem',
        fontWeight: 'bold',
        textAlign: 'left',
        flexBasis: '20%',
        flexShrink: 0
    },
    secondaryHeading: {
        fontSize: '1rem'
    },
    accordian: {
        cursor: 'pointer',
        '&:hover': {
            background: '#ebebeb'
        }
    }
}));

export default function SettingsPage(props) {
    const classes = useStyles();
    const [expanded, setExpanded] = React.useState(false);
    const [settingValues, setSettingValues] = useState([]);
    const [origSettingValues, setOrigSettingValues] = useState([]);
    const [, forceUpdate] = useReducer((x) => x + 1, 0);
    const [errorSnackbarMessage, setErrorSnackbarMessage] = useState('');
    const [successSnackbarMessage, setSuccessSnackbarMessage] = useState('');
    const [cron, setCron] = useState();

    let cache = props.cache;

    useEffect(() => {
        document.title = props.title;
    }, []);

    useEffect(() => {
        const settingsSub = serviceFactoryInstance.dataLoaderService.dataSub(ENTITY_NAME_SETTINGS).subscribe((data) => {
            if (data) {
                setSettingValues(config);
                setOrigSettingValues(data);
                let mapSettingValues = new Map();
                data.forEach((setting) => {
                    mapSettingValues.set(`${setting.category}_${setting.instance_name}`, setting);
                });
                if (settingValues.settingCategories) {
                    settingValues.settingCategories.forEach((category) => {
                        category.settings.forEach((setting) => {
                            let key = `${category.categoryName}_${setting.name}`;
                            let targetSetting = mapSettingValues.get(key);
                            if (targetSetting) {
                                let settingData = setting.data;
                                if (settingData) {
                                    setting.data.value = targetSetting.value;
                                }
                            }
                        });
                    });
                }
            }
        });

        return () => {
            settingsSub.unsubscribe();
        };
    }, [cache, settingValues.settingCategories]);

    const handleChange = (panel) => (event, isExpanded) => {
        setExpanded(isExpanded ? panel : false);
    };

    const handleSave = (event, categoryName) => {
        event.preventDefault();

        let copySettingValues = { ...origSettingValues };
        let mapSettingValues = new Map();
        for (let i = 0; i < Object.keys(copySettingValues).length; i++) {
            let setting = copySettingValues[i];
            mapSettingValues.set(`${setting.category}_${setting.instance_name}`, setting);
        }

        settingValues.settingCategories.forEach((category) => {
            if (category.categoryName === categoryName) {
                category.settings.forEach((setting) => {
                    const key = `${category.categoryName}_${setting.name}`;
                    const origSetting = mapSettingValues.get(key);
                    if (origSetting) {
                        origSetting.value = setting.data.value;
                    }
                });
            }
        });

        for (let i = 0; i < Object.keys(copySettingValues).length; i++) {
            let setting = copySettingValues[i];
            if (categoryName === setting.category) {
                serviceFactoryInstance.dataLoaderService
                    .updateInstance(ENTITY_NAME_SETTINGS, setting)
                    .then((data) => {
                        if (data.status) {
                            setSuccessSnackbarMessage('Settings updated');
                        } else {
                            setErrorSnackbarMessage('Failed to update settings');
                        }
                    })
                    .catch((reason) => {
                        console.log(reason);
                    });
            }
        }
    };

    const handleCancel = (categoryName) => {
        let mapSettingValues = new Map();
        origSettingValues.forEach((setting) => {
            mapSettingValues.set(`${setting.category}_${setting.instance_name}`, setting);
        });

        settingValues.settingCategories.forEach((category) => {
            if (category.categoryName === categoryName) {
                category.settings.forEach((setting) => {
                    const key = `${category.categoryName}_${setting.name}`;
                    const origSetting = mapSettingValues.get(key);
                    if (origSetting) {
                        setting.data.value = origSetting.value;
                    }
                });
            }
        });

        setSettingValues(settingValues);
        forceUpdate();
    };

    const handleValueChange = (setting, value) => {
        settingValues.settingCategories.forEach((category) => {
            category.settings.forEach((entry) => {
                if (entry.name === setting.name) {
                    entry.data.value = value;
                }
            });
        });
    };

    const getAccordians = (settings) => {
        let settingCategories = settings.settingCategories;
        if (!settings.settingCategories) {
            return <React.Fragment />;
        }

        return settingCategories.map((category) => {
            return (
                <Accordion
                    key={category.categoryName}
                    expanded={expanded === category.categoryName}
                    onChange={handleChange(category.categoryName)}
                >
                    <AccordionSummary
                        className={classes.accordian}
                        key={category.categoryName + '-summary'}
                        expandIcon={<CaretDownOutlined />}
                        aria-controls={`${category.categoryName}bh-content`}
                        id={`${category.categoryName}bh-header`}
                    >
                        <Typography variant="h6">{category.categoryDisplayName}</Typography>
                    </AccordionSummary>
                    <Divider key={category.categoryName + 'divider1'} />
                    <AccordionDetails key={category.categoryName + '-details'}>
                        <div style={{ width: '100%', paddingTop: '10px' }}>
                            <Grid container className={classes.root}>
                                {getSettings(category.settings)}
                            </Grid>
                        </div>
                    </AccordionDetails>
                    <Divider key={category.categoryName + '-divider2'} />
                    <AccordionActions key={category.categoryName + '-actions'}>
                        <Button
                            size="medium"
                            variant="contained"
                            color="secondary"
                            onClick={() => {
                                handleCancel(category.categoryName);
                            }}
                        >
                            Cancel
                        </Button>
                        <Button
                            size="medium"
                            variant="contained"
                            color="primary"
                            onClick={(event) => {
                                handleSave(event, category.categoryName);
                            }}
                        >
                            Save
                        </Button>
                    </AccordionActions>
                </Accordion>
            );
        });
    };

    const getSettings = (settings) => {
        return settings.map((setting) => {
            if (setting.type === 'toggle') {
                return (
                    <Grid item xs={6} style={{ paddingRight: '50px' }} key={setting.categoryName + setting.name}>
                        <ToggleSetting setting={setting} onValueChange={handleValueChange} />
                    </Grid>
                );
            } else if (setting.type === 'slider') {
                return (
                    <Grid item xs={6} style={{ paddingRight: '30px' }} key={setting.categoryName + setting.name}>
                        <SliderSetting setting={setting} onValueChange={handleValueChange} />
                    </Grid>
                );
            } else if (setting.type === 'text-input') {
                return (
                    <Grid item xs={6} style={{ paddingRight: '30px' }} key={setting.categoryName + setting.name}>
                        <TextInputSetting setting={setting} onValueChange={handleValueChange} />
                    </Grid>
                );
            } else if (setting.type === 'array') {
                return (
                    <Grid item xs={6} style={{ paddingRight: '30px' }} key={setting.categoryName + setting.name}>
                        <ArraySetting setting={setting} onValueChange={handleValueChange} />
                    </Grid>
                );
            } else if (setting.type === 'password') {
                return (
                    <Grid item xs={6} style={{ paddingRight: '30px' }} key={setting.categoryName + setting.name}>
                        <PasswordInputSetting setting={setting} onValueChange={handleValueChange} />
                    </Grid>
                );
            } else {
                return <React.Fragment />;
            }
        });
    };

    return (
        <div className={classes.root}>
            <CustomSnackbar msg={successSnackbarMessage} onClose={() => setSuccessSnackbarMessage('')} severity="success" title="Success" />
            <CustomSnackbar msg={errorSnackbarMessage} onClose={() => setErrorSnackbarMessage('')} severity="error" title="Error" />
            {getAccordians({ ...settingValues })}
        </div>
    );
}
