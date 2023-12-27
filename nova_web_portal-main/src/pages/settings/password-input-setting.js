import { IconButton, InputAdornment, TextField, Typography } from '../../../node_modules/@mui/material/index';
import { EyeOutlined, EyeInvisibleOutlined } from '@ant-design/icons';
import { useEffect, useState } from 'react';

export default function PasswordInputSetting(props) {
    const [value, setValue] = useState('');
    const [showPassword, setShowPassword] = useState(false);
    const handleClickShowPassword = () => setShowPassword(!showPassword);
    const handleMouseDownPassword = () => setShowPassword(!showPassword);

    useEffect(() => {
        setValue(props.setting.data.value !== undefined ? props.setting.data.value : props.setting.data.defaultValue);
    }, [props.setting.data.value, props.setting.data.defaultValue]);

    const handleInputChange = (e) => {
        setValue(e.target.value);
        props.onValueChange(props.setting, e.target.value);
    };

    return (
        <div style={{ paddingTop: '10px', paddingLeft: '20px', width: '100%' }}>
            <Typography style={{ textAlign: 'left', paddingBottom: '5px' }} variant="body1">
                <b>{props.setting.displayName}</b>
            </Typography>
            <Typography style={{ textAlign: 'left' }} variant="body2">
                {props.setting.description}
            </Typography>
            <TextField
                fullWidth
                required
                id={`${props.setting.type}_${props.setting.name}_value`}
                variant="standard"
                style={{ textAlign: 'left', paddingBottom: '20px', paddingRight: '20px' }}
                name={props.setting.name}
                onChange={handleInputChange}
                value={value || ''}
                type={showPassword ? 'text' : 'password'}
                InputProps={{
                    // <-- This is where the toggle button is added.
                    endAdornment: (
                        <InputAdornment position="end">
                            <IconButton
                                aria-label="toggle password EyeOutlined"
                                onClick={handleClickShowPassword}
                                onMouseDown={handleMouseDownPassword}
                            >
                                {showPassword ? <EyeOutlined /> : <EyeInvisibleOutlined />}
                            </IconButton>
                        </InputAdornment>
                    )
                }}
            />
        </div>
    );
}
