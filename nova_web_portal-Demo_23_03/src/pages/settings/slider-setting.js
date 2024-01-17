import { Slider, Typography } from '../../../node_modules/@mui/material/index';
import React, { useEffect } from 'react';

export default function SliderSetting(props) {
    const [value, setValue] = React.useState(0);

    useEffect(() => {
        setValue(props.setting.data.value !== undefined ? props.setting.data.value : props.setting.data.defaultValue);
    }, [props.setting.data.value, props.setting.data.defaultValue]);

    const handleInputChange = (e, newValue) => {
        setValue(newValue);
        props.onValueChange(props.setting, newValue);
    };

    return (
        <div style={{ paddingTop: '10px', paddingLeft: '20px' }}>
            <Typography style={{ textAlign: 'left', paddingBottom: '5px' }} variant="body1">
                <b>{props.setting.displayName}</b>
            </Typography>
            <Typography style={{ textAlign: 'left' }} variant="body2">
                {props.setting.description}
            </Typography>
            <Typography style={{ textAlign: 'left', paddingBottom: '20px', paddingLeft: '20px', paddingRight: '40px' }}>
                <Slider
                    id={`${props.setting.type}_${props.setting.name}_value`}
                    defaultValue={props.setting.data.defaultValue}
                    getAriaValueText={() => {}}
                    aria-labelledby="discrete-slider-always"
                    step={props.setting.data.step}
                    marks={props.setting.data.marks}
                    valueLabelDisplay={props.setting.data.showLabels}
                    value={value || 0}
                    onChange={handleInputChange}
                ></Slider>
            </Typography>
        </div>
    );
}
